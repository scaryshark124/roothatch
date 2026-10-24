// Package preflight performs a limited, unprivileged, read-only inspection of
// a Linux root tree. It resolves paths only inside the selected root, opens
// files only through descriptors obtained by that confined resolution, and
// never executes, mounts or modifies anything.
package preflight

import "strconv"

// Finding is one stable, human-readable problem report.
type Finding struct {
	Code   string // stable short code, e.g. "shell_missing"
	Path   string // in-root path the finding concerns (sanitized)
	Detail string // sanitized explanation
}

// Report is the result of Check.
type Report struct {
	Findings []Finding
	Interp   string // PT_INTERP of /bin/sh when one was parsed (sanitized)
	Static   bool   // /bin/sh is a valid x86-64 ELF64 without PT_INTERP
}

// RootError reports that the selected root itself cannot be used.
type RootError struct {
	Dir string
	Err error
}

func (e *RootError) Error() string { return e.Dir + ": " + e.Err.Error() }
func (e *RootError) Unwrap() error { return e.Err }

// ShellPath is the in-root path whose shell and interpreter are checked.
const ShellPath = "/bin/sh"

// clean makes untrusted tree data (link targets, ELF strings) safe for a
// single output line by escaping quotes, control and non-printable bytes.
func clean(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

func (r *Report) add(code, path, detail string) {
	r.Findings = append(r.Findings, Finding{Code: code, Path: clean(path), Detail: detail})
}
