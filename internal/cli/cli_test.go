package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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

// TestCheckFixtures exercises the real command path for every synthetic
// fixture and proves each tree is unchanged afterwards.
func TestCheckFixtures(t *testing.T) {
	for _, fx := range pt.Catalog() {
		t.Run(fx.Name, func(t *testing.T) {
			root := newRoot(t, fx.Entries...)
			before, err := pt.Digest(root)
			if err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run([]string{"check", root}, &out, &errOut, "v-test")
			after, err := pt.Digest(root)
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
			if !strings.HasPrefix(lines[len(lines)-1], "FAIL: ") {
				t.Errorf("summary = %q; want FAIL line", lines[len(lines)-1])
			}
			if strings.Contains(out.String(), root) {
				t.Errorf("output leaks host path of root: %q", out.String())
			}
		})
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
