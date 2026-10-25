package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// runBinaryIn executes the built command in working directory dir with a
// per-run timeout, passing args directly (no shell).
func runBinaryIn(t *testing.T, bin, dir string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = []string{"LC_ALL=C"}
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("binary did not finish within 20s: %v", ctx.Err())
	}
	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("cannot run binary: %v", err)
	}
	return code, stdout.String(), stderr.String()
}

// dashNames are sandbox directories whose names look like options or the
// delimiter. Each holds a healthy dynamic shell and interpreter and no
// /boot, so a full check reports kernel_missing and a shell-only check
// passes: the mode actually run is observable.
var dashNames = []string{"--shell-only", "--json", "-root", "--"}

// delimSandbox builds the dash-named trees plus ordinary trees d, e, a and b
// in one sandbox and returns it with its whole-sandbox manifest.
func delimSandbox(t *testing.T) (string, string) {
	t.Helper()
	sandbox := t.TempDir()
	var healthy []pt.Entry
	for _, f := range pt.ShellOnlyCatalog() {
		if f.Name == "so_dynamic_no_boot" {
			healthy = f.Entries
		}
	}
	if healthy == nil {
		t.Fatal("so_dynamic_no_boot not in ShellOnlyCatalog()")
	}
	for _, name := range append(append([]string{}, dashNames...), "d", "e", "a", "b") {
		var entries []pt.Entry
		for _, e := range healthy {
			e.Path = name + "/" + e.Path
			entries = append(entries, e)
		}
		if err := pt.Build(sandbox, entries...); err != nil {
			t.Fatal(err)
		}
	}
	before, err := pt.Digest(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, before
}

func requireUnchanged(t *testing.T, sandbox, before string, args []string) {
	t.Helper()
	after, err := pt.Digest(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("%q: manifest changed:\nbefore:\n%s\nafter:\n%s", args, before, after)
	}
}

// wantFull is the ordered (code, path) list of a full check of a healthy
// tree with no /boot; the shell-only check of the same tree has none.
var wantFull = []pt.FindingPair{{Code: "kernel_missing", Path: pt.BootPath}}

// checkDelimRun checks one accepted run: exit code, output kind, exact
// ordered findings, exact text and empty stderr.
func checkDelimRun(t *testing.T, args []string, code int, stdout, stderr string, asJSON, shellOnly bool) {
	t.Helper()
	want, wantCode, wantResult := wantFull, 3, "findings"
	if shellOnly {
		want, wantCode, wantResult = []pt.FindingPair{}, 0, "pass"
	}
	if code != wantCode || stderr != "" {
		t.Errorf("%q: exit %d stderr %q; want %d and empty stderr", args, code, stderr, wantCode)
	}
	if asJSON {
		r := checkJSONDocument(t, stdout)
		got := []pt.FindingPair{}
		for _, x := range r.Findings {
			got = append(got, pt.FindingPair{Code: x.Code, Path: x.Path})
		}
		if r.Result != wantResult || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: result %q findings %v; want %q %v", args, r.Result, got, wantResult, want)
		}
		return
	}
	if strings.HasPrefix(stdout, "{") || json.Valid([]byte(stdout)) {
		t.Errorf("%q: text mode wrote JSON:\n%s", args, stdout)
	}
	if shellOnly {
		w := "ok: /bin/sh is ELF64 little-endian x86-64; interpreter " + pt.Loader + " resolves inside the root\n" + pt.ShellOnlyPassLine + "\n"
		if stdout != w {
			t.Errorf("%q: text =\n%s\nwant\n%s", args, stdout, w)
		}
		return
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "kernel_missing: "+pt.BootPath+": ") ||
		lines[1] != "FAIL: 1 finding(s); the limited checks did not pass" {
		t.Errorf("%q: text =\n%s\nwant one kernel_missing at /boot and the FAIL line", args, stdout)
	}
}

// TestBinaryEndOfOptions runs every accepted "--" form through the compiled
// binary on directories literally named like options or "--": the operand
// after "--" is the directory and never selects JSON or shell-only mode.
// Each run must equal the legacy "./<name>" form with the same options.
func TestBinaryEndOfOptions(t *testing.T) {
	bin := buildBinary(t)
	sandbox, before := delimSandbox(t)
	prefixes := []struct {
		opts            []string
		asJSON, shellOn bool
	}{
		{nil, false, false},
		{[]string{"--json"}, true, false},
		{[]string{"--shell-only"}, false, true},
		{[]string{"--json", "--shell-only"}, true, true},
		{[]string{"--shell-only", "--json"}, true, true},
	}
	for _, name := range dashNames {
		for _, p := range prefixes {
			args := append(append(append([]string{"check"}, p.opts...), "--"), name)
			code, stdout, stderr := runBinaryIn(t, bin, sandbox, args...)
			requireUnchanged(t, sandbox, before, args)
			checkDelimRun(t, args, code, stdout, stderr, p.asJSON, p.shellOn)
			legacy := append(append([]string{"check"}, p.opts...), "./"+name)
			lc, lo, le := runBinaryIn(t, bin, sandbox, legacy...)
			requireUnchanged(t, sandbox, before, legacy)
			if lc != code || lo != stdout || le != stderr {
				t.Errorf("%q vs %q: exit %d/%d stdout %q/%q stderr %q/%q; want identical",
					args, legacy, code, lc, stdout, lo, stderr, le)
			}
		}
	}
}

// TestBinaryEndOfOptionsUsage: rejected "--" forms exit 2 with empty stdout
// and an explanation, even though directories named "--", d, e, a and b
// exist in the working directory (so bare "check --" and "check --json --"
// no longer check the directory "--"). The sandbox stays unchanged.
func TestBinaryEndOfOptionsUsage(t *testing.T) {
	bin := buildBinary(t)
	sandbox, before := delimSandbox(t)
	for _, args := range [][]string{
		{"check", "--"},
		{"check", "--json", "--"},
		{"check", "--shell-only", "--"},
		{"check", "--json", "--shell-only", "--"},
		{"check", "--", "a", "b"},
		{"check", "--", "--", "--"},
		{"check", "--json", "--json", "--", "d"},
		{"check", "--shell-only", "--shell-only", "--", "d"},
		{"check", "--bogus", "--", "d"},
		{"check", "-root", "--", "d"},
		{"check", "d", "--"},
		{"check", "d", "--", "e"},
		{"check", "--", "--roothatch-missing"},
	} {
		code, stdout, stderr := runBinaryIn(t, bin, sandbox, args...)
		requireUnchanged(t, sandbox, before, args)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty stdout, nonempty stderr", args, code, stdout, stderr)
		}
	}
}

// TestBinaryNoDelimiterLegacy: representative forms without "--" keep their
// previous meaning, including dash-named directories.
func TestBinaryNoDelimiterLegacy(t *testing.T) {
	bin := buildBinary(t)
	sandbox, before := delimSandbox(t)
	for _, tc := range []struct {
		args            []string
		asJSON, shellOn bool
	}{
		{[]string{"check", "-root"}, false, false},
		{[]string{"check", "--json", "--json"}, true, false},
		{[]string{"check", "--json", "-root"}, true, false},
		{[]string{"check", "--shell-only", "./-root"}, false, true},
		{[]string{"check", "./--"}, false, false},
		{[]string{"check", "--json", "./--"}, true, false},
	} {
		code, stdout, stderr := runBinaryIn(t, bin, sandbox, tc.args...)
		requireUnchanged(t, sandbox, before, tc.args)
		checkDelimRun(t, tc.args, code, stdout, stderr, tc.asJSON, tc.shellOn)
	}
	for _, args := range [][]string{{"check", "--shell-only", "-root"}, {"check", "-root", "--json"}} {
		code, stdout, stderr := runBinaryIn(t, bin, sandbox, args...)
		requireUnchanged(t, sandbox, before, args)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty stdout, nonempty stderr", args, code, stdout, stderr)
		}
	}
}

// TestBinaryEndOfOptionsOutputFailure: delimiter forms writing to /dev/full
// exit 1 with the output-failure message, in text and JSON.
func TestBinaryEndOfOptionsOutputFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); errors.Is(err, os.ErrNotExist) {
		t.Skip("/dev/full is absent")
	}
	bin := buildBinary(t)
	sandbox, _ := delimSandbox(t)
	for _, args := range [][]string{
		{"check", "--", "--json"},
		{"check", "--json", "--", "--shell-only"},
		{"check", "--shell-only", "--", "--json"},
		{"check", "--shell-only", "--json", "--", "-root"},
	} {
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = sandbox
		cmd.Stdout, cmd.Stderr = full, &stderr
		cmd.Env = []string{"LC_ALL=C"}
		err = cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		full.Close()
		if timedOut {
			t.Fatalf("%q: binary did not finish within 20s", args)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "cannot write output") {
			t.Errorf("%q: run error %v stderr %q; want exit 1 and output failure", args, err, stderr.String())
		}
	}
}
