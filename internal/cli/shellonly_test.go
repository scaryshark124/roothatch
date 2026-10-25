package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

func shellOnlyCat(t *testing.T) map[string]pt.ShellOnlyFixture {
	t.Helper()
	m := map[string]pt.ShellOnlyFixture{}
	for _, f := range pt.ShellOnlyCatalog() {
		m[f.Name] = f
	}
	return m
}

// shellOnlyText is the exact expected shell-only text output for f.
func shellOnlyText(f pt.ShellOnlyFixture, details []string) string {
	var b strings.Builder
	for i, p := range f.Shell {
		b.WriteString(p.Code + ": " + p.Path + ": " + details[i] + "\n")
	}
	if len(f.Shell) > 0 {
		return b.String() + "FAIL: " + strconv.Itoa(len(f.Shell)) + " finding(s); the limited checks did not pass\n"
	}
	if f.Static {
		b.WriteString("note: /bin/sh is a static ELF64 x86-64 file without PT_INTERP; interpreter check not applicable\n")
	} else {
		b.WriteString("ok: /bin/sh is ELF64 little-endian x86-64; interpreter " + f.Interp + " resolves inside the root\n")
	}
	return b.String() + pt.ShellOnlyPassLine + "\n"
}

// TestCheckShellOnlyForms runs every shell-only fixture through all accepted
// shell-only flag orders: exact text, strict JSON equal to the text finding
// block, exit codes, empty stderr and an unchanged sandbox.
func TestCheckShellOnlyForms(t *testing.T) {
	for _, f := range pt.ShellOnlyCatalog() {
		t.Run(f.Name, func(t *testing.T) {
			sandbox, root := fixtureRoot(t, f.Fixture())
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			wantCode, wantResult := 0, "pass"
			if len(f.Shell) > 0 {
				wantCode, wantResult = 3, "findings"
			}
			var details []string
			for _, args := range [][]string{{"check", "--json", "--shell-only", root}, {"check", "--shell-only", "--json", root}} {
				var out, errOut bytes.Buffer
				code := Run(args, &out, &errOut, "v")
				if code != wantCode || errOut.Len() != 0 {
					t.Errorf("%q: exit %d stderr %q; want %d, empty", args[1:3], code, errOut.String(), wantCode)
				}
				r := decodeStrict(t, out.Bytes())
				got := []pt.FindingPair{}
				details = nil
				for _, x := range r.Findings {
					got = append(got, pt.FindingPair{Code: x.Code, Path: x.Path})
					details = append(details, x.Detail)
				}
				if r.SchemaVersion != 1 || r.Result != wantResult || !reflect.DeepEqual(got, f.Shell) {
					t.Errorf("%q: json %+v; want result %s findings %v", args[1:3], r, wantResult, f.Shell)
				}
				var top map[string]json.RawMessage
				if err := json.Unmarshal(out.Bytes(), &top); err != nil || len(top) != 3 {
					t.Errorf("top-level keys %v (%v); want exactly 3", top, err)
				}
				if len(f.Shell) == 0 && string(bytes.TrimSpace(top["findings"])) != "[]" {
					t.Errorf("empty findings = %s; want []", top["findings"])
				}
			}
			var out, errOut bytes.Buffer
			code := Run([]string{"check", "--shell-only", root}, &out, &errOut, "v")
			if code != wantCode || errOut.Len() != 0 {
				t.Errorf("text: exit %d stderr %q; want %d, empty", code, errOut.String(), wantCode)
			}
			if want := shellOnlyText(f, details); out.String() != want {
				t.Errorf("text =\n%s\nwant\n%s", out.String(), want)
			}
			for _, s := range []string{"/boot has", "/vmlinuz resolves", "/initrd.img resolves", "optional shortcut link", "PASS: limited checks passed"} {
				if strings.Contains(out.String(), s) {
					t.Errorf("shell-only text contains boot/shortcut line %q:\n%s", s, out.String())
				}
			}
			after, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("manifest changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// TestCheckShellOnlyDefaultUnchanged: the same trees still give the full
// default findings in check and check --json.
func TestCheckShellOnlyDefaultUnchanged(t *testing.T) {
	for _, f := range pt.ShellOnlyCatalog() {
		t.Run(f.Name, func(t *testing.T) {
			_, root := fixtureRoot(t, f.Fixture())
			var out, errOut bytes.Buffer
			if code := Run([]string{"check", "--json", root}, &out, &errOut, "v"); code != 3 || errOut.Len() != 0 {
				t.Errorf("exit %d stderr %q; want 3", code, errOut.String())
			}
			got := []pt.FindingPair{}
			for _, x := range decodeStrict(t, out.Bytes()).Findings {
				got = append(got, pt.FindingPair{Code: x.Code, Path: x.Path})
			}
			if !reflect.DeepEqual(got, f.Default) {
				t.Errorf("default findings %v; want %v", got, f.Default)
			}
		})
	}
}

// TestCheckShellOnlyUsage: rejected forms exit 2 with empty stdout and an
// explanation; legacy invalid forms keep their exact legacy stderr.
func TestCheckShellOnlyUsage(t *testing.T) {
	root := newRoot(t, shellOnlyCat(t)["so_dynamic_no_boot"].Entries...)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "--shell-only"},
		{"check", "--shell-only", "--json"},
		{"check", "--json", "--shell-only"},
		{"check", "--shell-only", "--shell-only", root},
		{"check", "--json", "--shell-only", "--json", root},
		{"check", "--shell-only", "--json", "--shell-only", root},
		{"check", root, "--shell-only"},
		{"check", "--json", root, "--shell-only"},
		{"check", "--shell-only", root, "--json"},
		{"check", "--shell-only", root, root},
		{"check", "--shell-only", "--foo", root},
		{"check", "--shell-only=1", root},
		{"check", "-shell-only", root},
		{"check", "--Shell-Only", root},
		{"check", "--shell-only", filepath.Join(root, "missing")},
		{"check", "--shell-only", file},
		{"check", "--json", "--shell-only", file},
		{"check", "--shell-only", "--json", "/nonexistent-roothatch-test-dir"},
	} {
		var out, errOut bytes.Buffer
		if code := Run(args, &out, &errOut, "v"); code != 2 {
			t.Errorf("%q: exit = %d; want 2", args, code)
		}
		if out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("%q: stdout %q stderr %q; want empty stdout, nonempty stderr", args, out.String(), errOut.String())
		}
	}
	const one = "roothatch: check requires exactly one directory: roothatch check <dir>\n"
	const jsonOne = "roothatch: check --json requires exactly one directory: roothatch check --json <dir>\n"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"check"}, one},
		{[]string{"check", "a", "b"}, one},
		{[]string{"check", root, "--json"}, one},
		{[]string{"check", "--json", root, root}, one},
		{[]string{"check", "--json"}, jsonOne},
	} {
		var out, errOut bytes.Buffer
		if code := Run(tc.args, &out, &errOut, "v"); code != 2 || out.Len() != 0 || errOut.String() != tc.want {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty, %q", tc.args, code, out.String(), errOut.String(), tc.want)
		}
	}
}

func TestHelpDocumentsShellOnly(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut, "v"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, s := range []string{"roothatch check --shell-only <dir>", "roothatch check --json --shell-only <dir>",
		"/vmlinuz and /initrd.img", "only the checks requested", "may still resolve beneath /boot"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help lacks %q:\n%s", s, out.String())
		}
	}
}

func TestCheckShellOnlyOutputFailure(t *testing.T) {
	cat := shellOnlyCat(t)
	for _, name := range []string{"so_dynamic_no_boot", "so_missing_shell"} {
		root := newRoot(t, cat[name].Entries...)
		for _, args := range [][]string{{"check", "--shell-only", root}, {"check", "--json", "--shell-only", root}} {
			var errOut bytes.Buffer
			if code := Run(args, failingWriter{}, &errOut, "v"); code != 1 {
				t.Errorf("%s %q: exit = %d; want 1", name, args[1:len(args)-1], code)
			}
			if !strings.Contains(errOut.String(), "cannot write output") {
				t.Errorf("%s: stderr = %q", name, errOut.String())
			}
		}
	}
}
