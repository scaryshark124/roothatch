package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseCheckArgsDelimiter covers every accepted "--" form: the first
// "--" ends the options, only --json and --shell-only (each once, either
// order) may precede it, and the single argument after it is the directory,
// taken literally and never inspected as an option.
func TestParseCheckArgsDelimiter(t *testing.T) {
	for _, tc := range []struct {
		args            []string
		dir             string
		asJSON, shellOn bool
	}{
		{[]string{"--", "--shell-only"}, "--shell-only", false, false},
		{[]string{"--", "--json"}, "--json", false, false},
		{[]string{"--json", "--", "--shell-only"}, "--shell-only", true, false},
		{[]string{"--shell-only", "--", "--json"}, "--json", false, true},
		{[]string{"--json", "--shell-only", "--", "-root"}, "-root", true, true},
		{[]string{"--shell-only", "--json", "--", "-root"}, "-root", true, true},
		{[]string{"--", "--"}, "--", false, false},
		{[]string{"--", "-root"}, "-root", false, false},
		{[]string{"--", "d"}, "d", false, false},
		{[]string{"--json", "--", "d"}, "d", true, false},
		{[]string{"--shell-only", "--", "d"}, "d", false, true},
		{[]string{"--", "--json --shell-only"}, "--json --shell-only", false, false},
		{[]string{"--", ""}, "", false, false},
	} {
		var errOut bytes.Buffer
		dir, asJSON, shellOnly, ok := parseCheckArgs(tc.args, &errOut)
		if !ok || dir != tc.dir || asJSON != tc.asJSON || shellOnly != tc.shellOn || errOut.Len() != 0 {
			t.Errorf("%q: dir %q json %v shell-only %v ok %v stderr %q; want dir %q json %v shell-only %v ok, empty stderr",
				tc.args, dir, asJSON, shellOnly, ok, errOut.String(), tc.dir, tc.asJSON, tc.shellOn)
		}
	}
}

// TestParseCheckArgsDelimiterErrors: every rejected "--" form fails with an
// explanation, including the two compatibility changes (bare "--" and
// "--json --" no longer name a directory "--").
func TestParseCheckArgsDelimiterErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--"},
		{"--json", "--"},
		{"--shell-only", "--"},
		{"--json", "--shell-only", "--"},
		{"--", "a", "b"},
		{"--", "--", "--"},
		{"--", "--json", "d"},
		{"--json", "--json", "--", "d"},
		{"--shell-only", "--shell-only", "--", "d"},
		{"--json", "--shell-only", "--json", "--", "d"},
		{"--bogus", "--", "d"},
		{"-root", "--", "d"},
		{"--json=1", "--", "d"},
		{"-shell-only", "--", "d"},
		{"d", "--"},
		{"d", "--", "e"},
		{"--json", "d", "--", "e"},
		{"--shell-only", "d", "--"},
		{"", "--", "d"},
	} {
		var errOut bytes.Buffer
		dir, asJSON, shellOnly, ok := parseCheckArgs(args, &errOut)
		if ok || dir != "" || asJSON || shellOnly || errOut.Len() == 0 {
			t.Errorf("%q: dir %q json %v shell-only %v ok %v stderr %q; want rejection with an explanation",
				args, dir, asJSON, shellOnly, ok, errOut.String())
		}
		if !strings.HasPrefix(errOut.String(), "roothatch: check") || !strings.Contains(errOut.String(), "--") {
			t.Errorf("%q: stderr %q; want a roothatch check usage explanation", args, errOut.String())
		}
	}
}

// TestParseCheckArgsNoDelimiterUnchanged pins representative legacy forms
// without "--", which keep the previous parser and messages exactly.
func TestParseCheckArgsNoDelimiterUnchanged(t *testing.T) {
	for _, tc := range []struct {
		args            []string
		dir             string
		asJSON, shellOn bool
	}{
		{[]string{"-root"}, "-root", false, false},
		{[]string{"--json", "--json"}, "--json", true, false},
		{[]string{"--json", "-root"}, "-root", true, false},
		{[]string{"--shell-only", "./-root"}, "./-root", false, true},
		{[]string{"--json", "--shell-only", "./--json"}, "./--json", true, true},
		{[]string{"./--"}, "./--", false, false},
		{[]string{"---"}, "---", false, false},
	} {
		var errOut bytes.Buffer
		dir, asJSON, shellOnly, ok := parseCheckArgs(tc.args, &errOut)
		if !ok || dir != tc.dir || asJSON != tc.asJSON || shellOnly != tc.shellOn || errOut.Len() != 0 {
			t.Errorf("%q: dir %q json %v shell-only %v ok %v stderr %q; want %q %v %v ok",
				tc.args, dir, asJSON, shellOnly, ok, errOut.String(), tc.dir, tc.asJSON, tc.shellOn)
		}
	}
	const one = "roothatch: check requires exactly one directory: roothatch check <dir>\n"
	const so = "roothatch check [--json] --shell-only <dir>"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-root", "--json"}, one},
		{[]string{"--json", "--json", "--json"}, one},
		{[]string{"--shell-only", "-root"}, "roothatch: check: unknown flag \"-root\"; usage: " + so + "\n"},
		{[]string{"--shell-only", "--shell-only", "d"}, "roothatch: check: --shell-only given more than once; usage: " + so + "\n"},
	} {
		var errOut bytes.Buffer
		if _, _, _, ok := parseCheckArgs(tc.args, &errOut); ok || errOut.String() != tc.want {
			t.Errorf("%q: ok %v stderr %q; want rejection %q", tc.args, ok, errOut.String(), tc.want)
		}
	}
}

// TestCheckDelimiterUnusableDirectory: an unusable operand after "--" gets
// the same unusable-directory message, quoting the operand as given.
func TestCheckDelimiterUnusableDirectory(t *testing.T) {
	const missing = "--roothatch-test-missing-dir"
	for _, args := range [][]string{
		{"check", "--", missing},
		{"check", "--json", "--", missing},
		{"check", "--shell-only", "--", missing},
		{"check", "--shell-only", "--json", "--", missing},
	} {
		var out, errOut bytes.Buffer
		code := Run(args, &out, &errOut, "v")
		want := "roothatch: check: \"" + missing + "\" is not a usable directory: "
		if code != 2 || out.Len() != 0 || !strings.HasPrefix(errOut.String(), want) {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty stdout, prefix %q", args, code, out.String(), errOut.String(), want)
		}
	}
}

// TestCheckDelimiterSameOutput: a delimiter form renders byte-for-byte what
// the equivalent legacy form renders for the same root.
func TestCheckDelimiterSameOutput(t *testing.T) {
	root := newRoot(t, shellOnlyCat(t)["so_dynamic_no_boot"].Entries...)
	for _, tc := range []struct{ legacy, delim []string }{
		{[]string{"check", root}, []string{"check", "--", root}},
		{[]string{"check", "--json", root}, []string{"check", "--json", "--", root}},
		{[]string{"check", "--shell-only", root}, []string{"check", "--shell-only", "--", root}},
		{[]string{"check", "--json", "--shell-only", root}, []string{"check", "--shell-only", "--json", "--", root}},
	} {
		var lo, le, do, de bytes.Buffer
		lc := Run(tc.legacy, &lo, &le, "v")
		dc := Run(tc.delim, &do, &de, "v")
		if lc != dc || lo.String() != do.String() || le.String() != de.String() || de.Len() != 0 {
			t.Errorf("%q vs %q: exit %d/%d stdout %q/%q stderr %q/%q; want identical, empty stderr",
				tc.legacy, tc.delim, lc, dc, lo.String(), do.String(), le.String(), de.String())
		}
	}
}

func TestHelpDocumentsEndOfOptions(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut, "v"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, s := range []string{"roothatch check [--json] [--shell-only] -- <dir>", "either order",
		"must not be repeated", "roothatch check -- --", "./--"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help lacks %q:\n%s", s, out.String())
		}
	}
}
