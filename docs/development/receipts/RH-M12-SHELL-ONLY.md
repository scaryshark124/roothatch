# RH-M12 — `check --shell-only` receipt

Date: 2026-10-24. **Functional acceptance of a scoped check mode.** Not a
security PASS, bootability verdict, executable-environment guarantee or release.

## Delivered behavior

- `roothatch check --shell-only <dir>` and `roothatch check --json --shell-only
  <dir>` (flags before `<dir>`, either order, each once) run only the existing
  `/bin/sh` and ELF interpreter phase. The independent `/boot` kernel/initrd and
  `/vmlinuz`/`/initrd.img` phases are not invoked; findings are not filtered
  afterwards.
- Shell-only skips the boot phases, not every read beneath `/boot`: if `/bin/sh`
  or its PT_INTERP resolves under `/boot`, that file is still checked.
- On success the text output ends with a distinct line beginning `PASS: limited
  shell checks passed` that states `/boot`, `/vmlinuz` and `/initrd.img` were not
  checked and that this does not show the root is bootable or healthy.
- JSON stays schema version 1 with the same three fields; `result` covers only
  the checks requested. Exit codes are unchanged.
- Default `check <dir>` and `check --json <dir>` behavior is unchanged.
- Limits of the argument grammar: in shell-only mode a directory whose name
  starts with `-` must be written as `./-name`; a bare operand spelled exactly
  `--shell-only` is now read as the flag, not as a directory name.

## Executed verification

- Independent functional review: round 1 PASS, including source routing and a
  reviewer-run default-output comparison.
- Source boundary: `Check` selects the shell, boot and shortcut phases in their
  original order and `CheckShell` selects only the shell phase, both through one
  shared root admission. No check function, resolver, reader, ELF parser or CLI
  writer changed. No existing test or fixture file was modified.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed; the
  new shell-only unit and real-binary tests ran and no tests were skipped.
- On 117 synthetic fixture roots (105 existing catalog
  fixtures and 12 new shell-only fixtures), the previous
  release binary and the candidate gave byte-identical default text and JSON
  output (stdout, stderr and exit status) on every root.
- Shell-only output was compared with an independent oracle that called the
  previous release's own shell check directly on the same roots. On every root
  the shell-only JSON findings (code, path, detail and order) equalled the
  oracle, both flag orders gave identical JSON, the text output reproduced the
  same findings, stderr was empty and exit status matched. 28 roots pass in
  shell-only mode while the default check fails on boot findings, including a
  tree with no `/boot`, a static shell with no loader, broken or escaping boot
  links, and a valid interpreter under `/boot`.
- Argument forms: 23 pre-existing forms (including invalid
  ones and dash-prefixed directories) behaved byte-identically on both binaries;
  7 newly accepted forms were rejected by the previous
  release and accepted by the candidate; 13 malformed
  shell-only forms exited 2 with empty stdout and an explanation.
- Fail-closed manifests of every fixture sandbox (contents, modes, links and
  outside sentinels) were identical before and after every run.

## Limits

Synthetic fixtures only. Shell-only results say nothing about boot files.
RH-M2-01 and RH-M5-01 remain open; the M1 design remains held.
