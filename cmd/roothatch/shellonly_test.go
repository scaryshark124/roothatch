package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// runShellOnlyModes runs the compiled binary on root with each argument
// prefix in shellForms and checks exact exit, empty stderr, strict JSON with
// exact ordered (code, path) findings, that the text finding block equals the
// JSON findings in order, the exact verdict/pass lines, and an unchanged
// whole-sandbox manifest after every run.
func runShellOnlyModes(t *testing.T, bin, sandbox, root string, f pt.ShellOnlyFixture, before string) {
	t.Helper()
	wantCode, wantResult := 0, "pass"
	if len(f.Shell) > 0 {
		wantCode, wantResult = 3, "findings"
	}
	unchanged := func(what string) {
		t.Helper()
		after, err := pt.Digest(sandbox)
		if err != nil {
			t.Fatal(err)
		}
		if after != before {
			t.Errorf("%s: manifest changed:\nbefore:\n%s\nafter:\n%s", what, before, after)
		}
	}
	var rendered []string
	var firstJSON string
	for _, flags := range [][]string{{"--json", "--shell-only"}, {"--shell-only", "--json"}} {
		code, js, stderr := runBinary(t, bin, append(append([]string{"check"}, flags...), root)...)
		unchanged(strings.Join(flags, " "))
		if code != wantCode || stderr != "" {
			t.Errorf("%v: exit %d stderr %q; want %d and empty stderr", flags, code, stderr, wantCode)
		}
		r := checkJSONDocument(t, js)
		got := []pt.FindingPair{}
		rendered = []string{}
		for _, x := range r.Findings {
			got = append(got, pt.FindingPair{Code: x.Code, Path: x.Path})
			rendered = append(rendered, x.Code+": "+x.Path+": "+x.Detail)
		}
		if r.Result != wantResult || !reflect.DeepEqual(got, append([]pt.FindingPair{}, f.Shell...)) {
			t.Errorf("%v: result %q findings %v; want %q %v", flags, r.Result, got, wantResult, f.Shell)
		}
		if firstJSON == "" {
			firstJSON = js
		} else if js != firstJSON {
			t.Errorf("flag order changed JSON output:\n%s\n%s", firstJSON, js)
		}
	}
	code, text, stderr := runBinary(t, bin, "check", "--shell-only", root)
	unchanged("--shell-only")
	if code != wantCode || stderr != "" {
		t.Errorf("text: exit %d stderr %q; want %d and empty stderr", code, stderr, wantCode)
	}
	want := strings.Join(rendered, "\n")
	if len(rendered) > 0 {
		want += "\nFAIL: " + strconv.Itoa(len(rendered)) + " finding(s); the limited checks did not pass\n"
	} else if f.Static {
		want = "note: /bin/sh is a static ELF64 x86-64 file without PT_INTERP; interpreter check not applicable\n" + pt.ShellOnlyPassLine + "\n"
	} else {
		want = "ok: /bin/sh is ELF64 little-endian x86-64; interpreter " + f.Interp + " resolves inside the root\n" + pt.ShellOnlyPassLine + "\n"
	}
	if text != want {
		t.Errorf("text =\n%s\nwant\n%s", text, want)
	}
	if strings.Contains(text+firstJSON, root) {
		t.Errorf("output leaks host root path")
	}
}

// TestBinaryShellOnly runs every shell-only fixture through the compiled
// binary in shell-only text and both JSON flag orders, and in default text
// and --json modes, which must still report the full existing findings.
func TestBinaryShellOnly(t *testing.T) {
	bin := buildBinary(t)
	for _, f := range pt.ShellOnlyCatalog() {
		t.Run(f.Name, func(t *testing.T) {
			sandbox := t.TempDir()
			root, err := pt.BuildFixture(sandbox, f.Fixture())
			if err != nil {
				t.Fatal(err)
			}
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			runShellOnlyModes(t, bin, sandbox, root, f, before)
			got := runBothModes(t, bin, root, f.Default)
			if len(got) != len(f.Default) {
				t.Errorf("default findings %v; want %v", got, f.Default)
			}
			after, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Errorf("default runs changed manifest:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// TestBinaryShellOnlyUsage covers rejected shell-only forms and unusable
// directories: exit 2, empty stdout, explanation on stderr.
func TestBinaryShellOnlyUsage(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "--shell-only"},
		{"check", "--shell-only", "--json"},
		{"check", "--json", "--shell-only"},
		{"check", "--shell-only", "--shell-only", dir},
		{"check", "--json", "--json", "--shell-only", dir},
		{"check", dir, "--shell-only"},
		{"check", "--json", dir, "--shell-only"},
		{"check", "--shell-only", dir, "--json"},
		{"check", "--shell-only", dir, dir},
		{"check", "--shell-only", "--foo", dir},
		{"check", "--shell-only=1", dir},
		{"check", "-shell-only", dir},
		{"check", "--shell-only", filepath.Join(dir, "missing")},
		{"check", "--shell-only", file},
		{"check", "--json", "--shell-only", filepath.Join(dir, "missing")},
		{"check", "--shell-only", "--json", file},
	} {
		code, stdout, stderr := runBinary(t, bin, args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty stdout, nonempty stderr", args, code, stdout, stderr)
		}
	}
}

// TestBinaryShellOnlyOutputFailure writes shell-only text and JSON to
// /dev/full: an output failure must exit 1 for a passing and a findings tree.
func TestBinaryShellOnlyOutputFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); errors.Is(err, os.ErrNotExist) {
		t.Skip("/dev/full is absent")
	}
	bin := buildBinary(t)
	cat := map[string]pt.ShellOnlyFixture{}
	for _, f := range pt.ShellOnlyCatalog() {
		cat[f.Name] = f
	}
	for _, name := range []string{"so_dynamic_no_boot", "so_missing_shell"} {
		root, err := pt.BuildFixture(t.TempDir(), cat[name].Fixture())
		if err != nil {
			t.Fatal(err)
		}
		for _, flags := range [][]string{{"--shell-only"}, {"--json", "--shell-only"}, {"--shell-only", "--json"}} {
			full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			var stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, bin, append(append([]string{"check"}, flags...), root)...)
			cmd.Stdout, cmd.Stderr = full, &stderr
			cmd.Env = []string{"LC_ALL=C"}
			err = cmd.Run()
			timedOut := ctx.Err() != nil
			cancel()
			full.Close()
			if timedOut {
				t.Fatalf("%s %v: binary did not finish within 20s", name, flags)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "cannot write output") {
				t.Errorf("%s %v: run error %v stderr %q; want exit 1 and output failure", name, flags, err, stderr.String())
			}
		}
	}
}
