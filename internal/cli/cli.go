// Package cli implements the nonprivileged Roothatch command interface.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/scaryshark124/roothatch/internal/preflight"
)

const usage = `Roothatch — Build it. Fix it. Boot it.

Usage: roothatch [help|version]
       roothatch check <dir>
       roothatch check --json <dir>
       roothatch check --shell-only <dir>
       roothatch check --json --shell-only <dir>
       roothatch check [--json] [--shell-only] -- <dir>

check inspects the Linux root tree at <dir> read-only and without privileges.
It checks only that /bin/sh resolves inside <dir>, is an ELF64 little-endian
x86-64 file, and that its ELF interpreter (PT_INTERP) resolves inside <dir> to
a regular file whose ELF header declares ELF64 little-endian x86-64 and an
executable or shared-object type (ET_EXEC or ET_DYN). That is a header-level
check only; the loader is never run or otherwise validated. A valid /bin/sh
whose resolved regular file has no owner, group or other execute permission bit
is reported as shell_not_executable (mode bits only; not a check of whether any
user can run it); its interpreter is still checked. Likewise, an interpreter
whose header passes but whose resolved regular file has no execute permission
bit is reported as interp_not_executable at the PT_INTERP path (mode bits only).
Independently it applies Debian naming-convention consistency checks to the
in-tree <dir>/boot: at least one /boot/vmlinuz-<version> regular file, and a
matching /boot/initrd.img-<version> regular file for every such kernel; the
optional /vmlinuz and /initrd.img shortcut links, when present, must resolve
inside <dir> to regular files. File contents of kernels and initrds are not
read. Separate /boot or EFI partitions, bootloader configuration and initramfs
contents are not checked. Symlinks leaving <dir> are reported and never
followed onto the host.
Exit status: 0 limited checks passed, 3 findings reported, 2 usage error,
1 output failure. Passing does not show that <dir> is bootable or healthy.

check --json <dir> runs the same checks and writes one JSON document to stdout:
{"schema_version": 1, "result": "pass"|"findings", "findings": [{"code",
"path", "detail"}]}, with the same exit status. "pass" means only that the
current limited checks passed; it is not a bootability verdict. --json must
come before <dir> (directly after check unless --shell-only is also given);
usage errors write nothing to stdout.

check --shell-only <dir> runs only the /bin/sh and ELF interpreter checks above
and skips the independent /boot kernel/initrd checks and the /vmlinuz and
/initrd.img shortcut-link checks, for trees that have no boot files. /bin/sh or
its PT_INTERP may still resolve beneath /boot and are then checked there like
any other path. It reports the same shell findings and exit status as check;
its PASS line says /boot, /vmlinuz and /initrd.img were not checked. With
--json (before or after --shell-only; both flags before <dir>, each at most
once) it writes the same schema_version 1 document; its "result" covers
only the checks requested.

A "--" argument ends check's options, so a directory whose name begins with
"-" can be checked: roothatch check [--json] [--shell-only] -- <dir>. Only
--json and --shell-only may come before the first "--", each at most once, in
either order; anything else there is a usage error. Exactly one argument must
follow it, and that argument is the directory, taken literally even when it
looks like an option: "check -- --json" checks the directory "--json" in text
mode, and "check -- --shell-only" runs the full check on the directory
"--shell-only". "--" must not be repeated as a delimiter; a directory named
"--" is checked with roothatch check -- -- or roothatch check ./--. A bare
"check --" or "check --json --" names no directory and is a usage error.

Help, version and check are the only implemented commands in this pre-alpha.
Native entry, repair, image management and VM boot are not implemented.
Do not run this scaffold as root or use it to repair an installation.
`

// Run returns 0 for success, 1 for output failure, 2 for invalid usage, or
// 3 when check reports findings. It executes no subprocesses, requires no
// privileges and inspects a target only for "check", read-only.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	command := "help"
	if len(args) > 0 {
		command = args[0]
	}
	var output string
	switch command {
	case "help", "--help", "-h":
		output = usage
	case "version", "--version":
		output = "Roothatch " + version + "\n"
	case "check":
		return runCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "roothatch: unknown command %q; use 'roothatch help'\n", command)
		return 2
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "roothatch: %q does not accept arguments\n", command)
		return 2
	}
	return write(stdout, stderr, output, 0)
}

func write(stdout, stderr io.Writer, output string, code int) int {
	if _, err := io.WriteString(stdout, output); err != nil {
		fmt.Fprintln(stderr, "roothatch: cannot write output")
		return 1
	}
	return code
}

// jsonFinding and jsonReport are the schema_version 1 JSON output of
// "check --json". They carry exactly the documented fields.
type jsonFinding struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type jsonReport struct {
	SchemaVersion int           `json:"schema_version"`
	Result        string        `json:"result"`
	Findings      []jsonFinding `json:"findings"`
}

const shellOnlyFlag = "--shell-only"

func runCheck(args []string, stdout, stderr io.Writer) int {
	dir, asJSON, shellOnly, ok := parseCheckArgs(args, stderr)
	if !ok {
		return 2
	}
	check := preflight.Check
	if shellOnly {
		check = preflight.CheckShell
	}
	report, err := check(dir)
	if err != nil {
		fmt.Fprintf(stderr, "roothatch: check: %q is not a usable directory: %v\n", dir, err)
		return 2
	}
	switch {
	case asJSON:
		return writeJSON(report, stdout, stderr)
	case shellOnly:
		return writeShellText(report, stdout, stderr)
	}
	return writeText(report, stdout, stderr)
}

// endOfOptions is the argument that ends check's options.
const endOfOptions = "--"

// parseCheckArgs accepts only "check <dir>", "check --json <dir>",
// "check --shell-only <dir>" and "check --json --shell-only <dir>" in either
// flag order. Without --shell-only it keeps the previous parser and messages
// exactly. When any argument is exactly "--", parseDelimitedCheckArgs
// handles the arguments instead. It writes an explanation to stderr when it
// rejects the arguments.
func parseCheckArgs(args []string, stderr io.Writer) (dir string, asJSON, shellOnly, ok bool) {
	for i, a := range args {
		if a == endOfOptions {
			return parseDelimitedCheckArgs(args[:i], args[i+1:], stderr)
		}
	}
	for _, a := range args {
		if a == shellOnlyFlag {
			shellOnly = true
		}
	}
	if !shellOnly {
		// The previous accepted forms: "check <dir>" and "check --json <dir>".
		// A bare "check --json" is rejected rather than read as a directory.
		asJSON = len(args) == 2 && args[0] == "--json"
		if asJSON {
			args = args[1:]
		} else if len(args) == 1 && args[0] == "--json" {
			fmt.Fprintln(stderr, "roothatch: check --json requires exactly one directory: roothatch check --json <dir>")
			return "", false, false, false
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "roothatch: check requires exactly one directory: roothatch check <dir>")
			return "", false, false, false
		}
		return args[0], asJSON, false, true
	}
	const form = "roothatch check [--json] --shell-only <dir>"
	shellOnly = false
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a != "--json" && a != shellOnlyFlag {
			break
		}
		if (a == "--json" && asJSON) || (a == shellOnlyFlag && shellOnly) {
			fmt.Fprintf(stderr, "roothatch: check: %s given more than once; usage: %s\n", a, form)
			return "", false, false, false
		}
		if a == "--json" {
			asJSON = true
		} else {
			shellOnly = true
		}
	}
	rest := args[i:]
	if len(rest) != 1 {
		fmt.Fprintf(stderr, "roothatch: check requires exactly one directory after its flags; flags must come before it: %s\n", form)
		return "", false, false, false
	}
	// --shell-only is present, and any occurrence not consumed above would
	// leave more than one operand, so shellOnly is set here.
	if strings.HasPrefix(rest[0], "-") {
		fmt.Fprintf(stderr, "roothatch: check: unknown flag %q; usage: %s\n", rest[0], form)
		return "", false, false, false
	}
	return rest[0], asJSON, true, true
}

// parseDelimitedCheckArgs parses "check [--json] [--shell-only] -- <dir>",
// split at the first "--": opts may hold only --json and --shell-only, each
// at most once and in either order, and operands must be exactly one
// argument, which is the directory taken literally and never inspected as
// an option.
func parseDelimitedCheckArgs(opts, operands []string, stderr io.Writer) (dir string, asJSON, shellOnly, ok bool) {
	const form = "roothatch check [--json] [--shell-only] -- <dir>"
	for _, a := range opts {
		switch {
		case (a == "--json" && asJSON) || (a == shellOnlyFlag && shellOnly):
			fmt.Fprintf(stderr, "roothatch: check: %s given more than once before --; usage: %s\n", a, form)
			return "", false, false, false
		case a == "--json":
			asJSON = true
		case a == shellOnlyFlag:
			shellOnly = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "roothatch: check: unknown flag %q before --; usage: %s\n", a, form)
			return "", false, false, false
		default:
			fmt.Fprintf(stderr, "roothatch: check: the directory %q must come after --, not before it; usage: %s\n", a, form)
			return "", false, false, false
		}
	}
	if len(operands) != 1 {
		fmt.Fprintf(stderr, "roothatch: check requires exactly one directory after --; usage: %s\n", form)
		return "", false, false, false
	}
	return operands[0], asJSON, shellOnly, true
}

// writeJSON serializes report as one JSON document, preserving finding order
// and the report's sanitized strings. Exit 0 pass, 3 findings, 1 output failure.
func writeJSON(report preflight.Report, stdout, stderr io.Writer) int {
	doc := jsonReport{SchemaVersion: 1, Result: "pass", Findings: make([]jsonFinding, 0, len(report.Findings))}
	for _, f := range report.Findings {
		doc.Findings = append(doc.Findings, jsonFinding{Code: f.Code, Path: f.Path, Detail: f.Detail})
	}
	code := 0
	if len(doc.Findings) > 0 {
		doc.Result, code = "findings", 3
	}
	if err := json.NewEncoder(stdout).Encode(doc); err != nil {
		fmt.Fprintln(stderr, "roothatch: cannot write output")
		return 1
	}
	return code
}

func writeText(report preflight.Report, stdout, stderr io.Writer) int {
	var b strings.Builder
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "%s: %s: %s\n", f.Code, f.Path, f.Detail)
	}
	if n := len(report.Findings); n > 0 {
		fmt.Fprintf(&b, "FAIL: %d finding(s); the limited checks did not pass\n", n)
		return write(stdout, stderr, b.String(), 3)
	}
	if report.Static {
		b.WriteString("note: /bin/sh is a static ELF64 x86-64 file without PT_INTERP; interpreter check not applicable\n")
	} else {
		fmt.Fprintf(&b, "ok: /bin/sh is ELF64 little-endian x86-64; interpreter %s resolves inside the root\n", report.Interp)
	}
	fmt.Fprintf(&b, "ok: /boot has Debian-named kernel(s) with matching initrd: %s\n", strings.Join(report.Kernels, ", "))
	for _, l := range report.Links {
		if l.OK {
			fmt.Fprintf(&b, "ok: %s resolves inside the root to %s, a regular file\n", l.Path, l.Resolved)
		} else {
			fmt.Fprintf(&b, "note: %s not present (optional shortcut link)\n", l.Path)
		}
	}
	b.WriteString("PASS: limited checks passed (shell, ELF architecture, interpreter, Debian /boot kernel/initrd naming, optional /vmlinuz and /initrd.img links, symlink containment); this does not show the root is bootable or healthy\n")
	return write(stdout, stderr, b.String(), 0)
}

// shellOnlyPass is the final line of a passing "check --shell-only".
const shellOnlyPass = "PASS: limited shell checks passed (shell, ELF architecture, interpreter file type and ELF header, " +
	"shell and interpreter execute bits, symlink containment); /boot, /vmlinuz and /initrd.img were not checked as boot files; " +
	"this does not show the root is bootable or healthy\n"

// writeShellText renders a CheckShell report: the same finding and FAIL
// lines as writeText, or on a pass only the shell/interpreter line and the
// limited shell PASS line. Exit 0 pass, 3 findings, 1 output failure.
func writeShellText(report preflight.Report, stdout, stderr io.Writer) int {
	var b strings.Builder
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "%s: %s: %s\n", f.Code, f.Path, f.Detail)
	}
	if n := len(report.Findings); n > 0 {
		fmt.Fprintf(&b, "FAIL: %d finding(s); the limited checks did not pass\n", n)
		return write(stdout, stderr, b.String(), 3)
	}
	if report.Static {
		b.WriteString("note: /bin/sh is a static ELF64 x86-64 file without PT_INTERP; interpreter check not applicable\n")
	} else {
		fmt.Fprintf(&b, "ok: /bin/sh is ELF64 little-endian x86-64; interpreter %s resolves inside the root\n", report.Interp)
	}
	b.WriteString(shellOnlyPass)
	return write(stdout, stderr, b.String(), 0)
}
