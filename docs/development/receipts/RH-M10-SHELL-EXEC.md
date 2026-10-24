# RH-M10 — `/bin/sh` execute permission bits receipt

Date: 2026-10-24. **Functional acceptance of a mode-bit diagnostic.** Not a
security PASS, effective-access or bootability verdict, or release.

## Delivered behavior

- After `/bin/sh` resolves inside the root to a regular file and passes the
  existing ELF checks, `check` tests the mode bits from the stat the confined
  resolver already returned. If no owner, group or other execute bit is set, it
  reports `shell_not_executable` at `/bin/sh`, naming the mode.
- The check does not stop the scan: a static shell is still reported as static,
  and a dynamic shell's interpreter checks still run and their findings follow.
- Earlier shell failures (missing, escaping, looping, non-regular, unreadable,
  malformed, wrong architecture) keep only their existing finding.
- Any single execute bit passes. No new stat, open, read or access check is made.
  Unchanged: the resolver, reader, ELF and interpreter checks, `/boot`, kernel,
  initrd and shortcut checks, `ok:`/`PASS:` lines, exit codes and JSON schema 1.
- Test fixtures gained an optional explicit file mode, applied with a checked
  chmod only to a regular file just written; unset keeps the earlier behavior.

## Executed verification

- Independent functional review: round 1 PASS, including the mode-bit rule and
  finding precedence.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed; the
  new real-binary permission and unreadable-shell tests ran and no tests were
  skipped. The only production change is one block in `checkShell`, placed after
  ELF validation and before the static return, with no early return.
- Fixture catalog: all 86 earlier fixtures are unchanged with no mode
  set. The 6 new fixtures set a mode only on `/bin/sh`, and each shell's
  on-disk mode was confirmed before any binary ran.
- The previous release binary and the candidate ran on the same 92
  fixture trees in text and `--json` modes. 89 produced
  byte-identical stdout, stderr and exit status, including shells with only the
  owner (0744), group (0654) or other (0645) execute bit. Only three fixtures
  changed: dynamic and static shells at 0644 went from pass to exactly
  `shell_not_executable` (exit 3); a 0644 shell with a missing interpreter gained
  `shell_not_executable` before the unchanged `interp_missing`, with the FAIL
  count rising from 1 to 2.
- Precedence probes: malformed and AArch64 shells at 0644 gave identical output
  on both binaries, with only `elf_invalid` and `arch_unsupported` respectively.
- A mode-000 shell, run unprivileged with read denial confirmed, gave the same
  `read_error` on both binaries; content was restored and verified.
- JSON findings reproduced the text block, stderr was empty, and fail-closed
  sandbox manifests including file modes were identical before and after every
  run. Unchanged sentinels show they were not modified, not that they were not
  read.

## Limits

Mode bits only: no ACL, ownership, `noexec` mount, capability, setuid or
effective-access check, and the interpreter's permission bits are not checked.
Synthetic fixtures only. RH-M2-01 and RH-M5-01 remain open; the M1 design remains
held.
