# RH-M13 — `--` ends options for `check` receipt

Date: 2026-10-25. **Functional acceptance of an argument-grammar change.** Not a
security PASS, bootability verdict or release.

## Delivered behavior

- `roothatch check [--json] [--shell-only] -- <dir>`: the first argument that is
  exactly `--` ends options. Before it, only `--json` and `--shell-only` are
  accepted, each at most once, in either order. Exactly one argument must follow
  it, and that argument is the directory, taken literally even if it looks like
  an option. So `check -- --shell-only` runs the full check on a directory named
  `--shell-only`, `check -- --json` is text output, and `check -- --` checks a
  directory named `--`.
- Without a standalone `--`, the existing parser runs unchanged, including
  `check -root` and `check --json --json`.
- Two intended compatibility changes: bare `check --` and `check --json --`
  previously checked a directory named `--`; they are now usage errors (exit 2).
  That directory is still reachable as `check -- --` or `check ./--`.
- This removes RH-M12's need to write a dash-prefixed directory as `./-name` in
  shell-only mode; `./-name` still works. RH-M12's receipt remains as written.
- No change to the checks, findings, output writers, exit codes or JSON schema 1.

## Executed verification

- Independent functional review: round 1 PASS, including that the operand after
  `--` can never select a mode.
- Source boundary: no `internal/preflight` or `cmd/roothatch` production file
  changed. In `internal/cli/cli.go`, the existing parser body is unchanged apart
  from a prologue that hands delimiter forms to a new parse-only function; the
  check, writer and dispatch functions are unchanged. No existing test or
  fixture file was modified.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed; the
  10 new parser and real-binary tests ran and no tests were skipped.
- On 117 synthetic fixture roots, in full text, full JSON, shell-only
  text and shell-only JSON (both flag orders), the previous release and the
  candidate gave byte-identical stdout, stderr and exit status without `--`, and
  the candidate's `-- <root>` form was byte-identical to the previous release's
  plain form (1755 runs). Fixture sandboxes, including outside
  sentinels, were unchanged after every run.
- Directories named `--shell-only`, `--json`, `-root` and `--`, each holding a
  healthy shell and no `/boot`, were checked after `--` with every option set
  (20 cases). Each matched the previous release on `./<name>` byte for
  byte, and independently showed the requested mode only: full checks reported
  `kernel_missing` (exit 3), shell-only passed, and JSON appeared only with
  `--json`.
- 14 malformed delimiter forms (missing or extra operand, duplicate or
  unknown options, an operand before `--`) were rejected by the parser with
  exit 2 and empty stdout; 6 unusable directories after `--`
  (including `--bogus`) were reported as unusable directories quoting the
  operand as given; 31 pre-existing forms without `--` were
  byte-identical; and the two compatibility changes were confirmed with a real
  `--` directory present.

## Limits

Synthetic fixtures only. Options after the directory, short options and
`--opt=value` are not supported. RH-M2-01 and RH-M5-01 remain open; the M1 design
remains held.
