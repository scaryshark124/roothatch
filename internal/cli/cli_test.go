package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

func TestRun(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"no args", nil, 0, "Usage: roothatch", ""},
		{"help", []string{"help"}, 0, "roothatch check <dir>", ""},
		{"help flag", []string{"--help"}, 0, "Usage: roothatch", ""},
		{"short help", []string{"-h"}, 0, "Usage: roothatch", ""},
		{"version", []string{"version"}, 0, "Roothatch v-test\n", ""},
		{"version flag", []string{"--version"}, 0, "Roothatch v-test\n", ""},
		{"unknown", []string{"wat"}, 2, "", "unknown command"},
		{"planned enter", []string{"enter", "/not/a/real/target"}, 2, "", "unknown command"},
		{"planned boot", []string{"boot"}, 2, "", "unknown command"},
		{"planned doctor", []string{"doctor"}, 2, "", "unknown command"},
		{"version extra", []string{"version", "oops"}, 2, "", "does not accept arguments"},
		{"help extra", []string{"help", "oops"}, 2, "", "does not accept arguments"},
		{"flag extra", []string{"--version", "oops"}, 2, "", "does not accept arguments"},
		{"check no dir", []string{"check"}, 2, "", "check requires exactly one directory"},
		{"check extra", []string{"check", "a", "b"}, 2, "", "check requires exactly one directory"},
		{"check absent dir", []string{"check", "/nonexistent-roothatch-test-dir"}, 2, "", "not a usable directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut, "v-test")
			if code != tc.code {
				t.Errorf("exit = %d; want %d", code, tc.code)
			}
			for _, stream := range []struct{ name, got, want string }{
				{"stdout", out.String(), tc.stdout}, {"stderr", errOut.String(), tc.stderr},
			} {
				if stream.want == "" && stream.got != "" {
					t.Errorf("%s = %q; want empty", stream.name, stream.got)
				}
				if stream.want != "" && !strings.Contains(stream.got, stream.want) {
					t.Errorf("%s = %q; want %q", stream.name, stream.got, stream.want)
				}
			}
			if tc.name == "version" && out.String() != "Roothatch v-test\n" {
				t.Error("version output not exact")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

func TestOutputFailureIsNotSuccess(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}} {
		var errOut bytes.Buffer
		if code := Run(args, failingWriter{}, &errOut, "v-test"); code != 1 {
			t.Errorf("exit = %d; want 1", code)
		}
		if !strings.Contains(errOut.String(), "cannot write output") {
			t.Errorf("missing output failure: %q", errOut.String())
		}
	}
}

func newRoot(t *testing.T, entries ...pt.Entry) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := pt.Build(root, entries...); err != nil {
		t.Fatal(err)
	}
	return root
}

// fixtureRoot builds fx (including any outside-root sentinels) in a fresh
// sandbox and returns the sandbox and its root.
func fixtureRoot(t *testing.T, fx pt.Fixture) (string, string) {
	t.Helper()
	sandbox := t.TempDir()
	root, err := pt.BuildFixture(sandbox, fx)
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, root
}

// TestCheckFixtures exercises the real command path for every synthetic
// fixture and proves each tree (and outside sentinel) is unchanged afterwards.
func TestCheckFixtures(t *testing.T) {
	for _, fx := range pt.Catalog() {
		t.Run(fx.Name, func(t *testing.T) {
			sandbox, root := fixtureRoot(t, fx)
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run([]string{"check", root}, &out, &errOut, "v-test")
			after, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("fixture changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if errOut.Len() != 0 {
				t.Errorf("stderr = %q; want empty", errOut.String())
			}
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			if len(fx.Want) == 0 {
				if code != 0 {
					t.Fatalf("exit = %d; want 0; stdout %q", code, out.String())
				}
				if !strings.HasPrefix(lines[len(lines)-1], "PASS: limited checks passed") {
					t.Errorf("stdout = %q; want limited PASS line", out.String())
				}
				low := strings.ToLower(out.String())
				if !strings.Contains(low, "does not show") || !strings.Contains(low, "bootable") {
					t.Errorf("PASS output must disclaim bootability: %q", out.String())
				}
				checkBootPassLines(t, fx, out.String())
				return
			}
			if code != 3 {
				t.Fatalf("exit = %d; want 3; stdout %q", code, out.String())
			}
			if len(lines) != len(fx.Want)+1 {
				t.Fatalf("stdout lines = %q; want %d findings + summary", lines, len(fx.Want))
			}
			for i, c := range fx.Want {
				if !strings.HasPrefix(lines[i], c+": ") {
					t.Errorf("line %d = %q; want prefix %q", i, lines[i], c+": ")
				}
			}
			for i, p := range fx.Findings {
				if i < len(lines) && !strings.HasPrefix(lines[i], p.Code+": "+p.Path+": ") {
					t.Errorf("line %d = %q; want prefix %q", i, lines[i], p.Code+": "+p.Path+": ")
				}
			}
			if !strings.HasPrefix(lines[len(lines)-1], "FAIL: ") {
				t.Errorf("summary = %q; want FAIL line", lines[len(lines)-1])
			}
			if strings.Contains(out.String(), root) {
				t.Errorf("output leaks host path of root: %q", out.String())
			}
		})
	}
}

// checkBootPassLines asserts the passing output reports the Debian kernels
// found and the actual status of each optional shortcut link.
func checkBootPassLines(t *testing.T, fx pt.Fixture, out string) {
	t.Helper()
	want := "ok: /boot has Debian-named kernel(s) with matching initrd: " + strings.Join(fx.Kernels, ", ") + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("stdout = %q; want line %q", out, want)
	}
	present := map[string]bool{}
	for _, s := range fx.Shortcuts {
		present[s] = true
	}
	for _, link := range []string{"/vmlinuz", "/initrd.img"} {
		okLine := "ok: " + link + " resolves inside the root to "
		absent := "note: " + link + " not present (optional shortcut link)\n"
		if present[link] && (!strings.Contains(out, okLine) || strings.Contains(out, absent)) {
			t.Errorf("stdout = %q; want %q and not %q", out, okLine, absent)
		}
		if !present[link] && (!strings.Contains(out, absent) || strings.Contains(out, okLine)) {
			t.Errorf("stdout = %q; want %q and not %q", out, absent, okLine)
		}
	}
	if !strings.Contains(out, "Debian /boot kernel/initrd naming") {
		t.Errorf("PASS line must list the boot checks: %q", out)
	}
}

func TestHelpListsBootChecks(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut, "v"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, s := range []string{"/boot", "vmlinuz-<version>", "initrd.img-<version>", "/vmlinuz", "/initrd.img",
		"Debian", "does not show that <dir> is bootable"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help lacks %q:\n%s", s, out.String())
		}
	}
}

func TestCheckRegularFileIsUsage(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"check", file}, &out, &errOut, "v"); code != 2 {
		t.Fatalf("exit = %d; want 2", code)
	}
	if out.Len() != 0 || !strings.Contains(errOut.String(), "not a usable directory") {
		t.Errorf("stdout %q stderr %q", out.String(), errOut.String())
	}
}

func TestCheckOutputFailure(t *testing.T) {
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	for _, name := range []string{"healthy_merged_usr", "missing_shell"} {
		root := newRoot(t, cat[name].Entries...)
		var errOut bytes.Buffer
		if code := Run([]string{"check", root}, failingWriter{}, &errOut, "v"); code != 1 {
			t.Errorf("%s: exit = %d; want 1", name, code)
		}
		if !strings.Contains(errOut.String(), "cannot write output") {
			t.Errorf("%s: stderr = %q", name, errOut.String())
		}
	}
}

// TestHelpDocumentsInterpExec: help names the interpreter mode-bit finding
// and its limited meaning, and keeps the implemented-command sentence.
func TestHelpDocumentsInterpExec(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut, "v"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, s := range []string{"interp_not_executable", "shell_not_executable", "mode bits only"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help lacks %q:\n%s", s, out.String())
		}
	}
}

// TestCheckInterpNoExecLines pins the exact text finding lines for a
// non-executable shell and loader through the real command path.
func TestCheckInterpNoExecLines(t *testing.T) {
	var fx pt.Fixture
	for _, f := range pt.Catalog() {
		if f.Name == "interp_noexec_shell_noexec" {
			fx = f
		}
	}
	if fx.Name == "" {
		t.Fatal("interp_noexec_shell_noexec not in Catalog()")
	}
	_, root := fixtureRoot(t, fx)
	var out, errOut bytes.Buffer
	if code := Run([]string{"check", root}, &out, &errOut, "v"); code != 3 || errOut.Len() != 0 {
		t.Fatalf("exit = %d stderr %q; want 3 and empty", code, errOut.String())
	}
	detail := ": resolves to a regular file with mode 0644; no owner, group or other execute bit is set " +
		"(mode bits only; not a check of whether any user can run it)"
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := []string{"shell_not_executable: /bin/sh" + detail, "interp_not_executable: " + pt.Loader + detail}
	if len(lines) != 3 || !reflect.DeepEqual(lines[:2], want) || !strings.HasPrefix(lines[2], "FAIL: ") {
		t.Errorf("stdout lines = %q; want %q then FAIL", lines, want)
	}
}
