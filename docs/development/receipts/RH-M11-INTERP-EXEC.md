# RH-M11 — ELF interpreter execute permission bits receipt

Date: 2026-10-24. **Functional acceptance of a mode-bit diagnostic.** Not a
security PASS, effective-access, loader-functionality or bootability verdict, or
release.

## Delivered behavior

- After the interpreter resolves inside the root to a regular file and passes
  the existing header, architecture and type checks, `check` tests the mode bits
  from the interpreter's own stat, already returned by the confined resolver.
  If no owner, group or other execute bit is set, it reports
  `interp_not_executable` at the PT_INTERP path, naming the mode.
- For a symlinked interpreter the resolved target's mode is used; the finding is
  reported at the PT_INTERP path.
- Read failures and interpreter header, architecture and type findings keep only
  their existing finding. `/bin/sh` findings are unchanged, so a non-executable
  shell and loader report `shell_not_executable` then `interp_not_executable`.
  Static shells still do no interpreter work.
- Any single execute bit passes. No new stat, open, read or access check is made.
  Unchanged: the resolver, reader, ELF parsers, `/boot`, kernel, initrd and
  shortcut checks, `ok:`/`PASS:` lines, exit codes and JSON schema 1.

## Executed verification

- Independent functional review: round 1 PASS, including use of the
  interpreter's stat, finding precedence and absence of new filesystem calls.
- One existing unit-test expectation changed, as authorized in the card: a
  `TestShellExecPrecedence` case that pinned the earlier "interpreter mode not
  checked" boundary now expects `interp_not_executable`. No other existing test
  expectation or fixture changed.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed; the
  new real-binary permission and unreadable-interpreter tests ran and no tests
  were skipped. The only production logic change is one branch on the
  interpreter-header success path.
- Fixture catalog: all 92 earlier fixtures are identical. For the
  13 new fixtures, modes, links and loader headers were checked in the
  definitions and on disk before any binary ran.
- The previous release binary and the candidate ran on the same 105
  fixture trees in text and `--json` modes. 102 produced
  byte-identical stdout, stderr and exit status, including loaders with a single
  execute bit, a symlink to an executable loader, an `ET_EXEC` loader, a static
  shell beside an unused 0644 loader, and malformed, AArch64 and `ET_REL` loaders
  at 0644. Only three fixtures changed: an executable shell with a 0644 loader,
  and a symlink to a 0644 loader, went from pass to exactly
  `interp_not_executable` (exit 3); a 0644 shell with a 0644 loader kept its
  exact `shell_not_executable` and gained `interp_not_executable`, with the FAIL
  count rising from 1 to 2.
- A mode-000 loader, run unprivileged with read denial confirmed, gave the same
  `read_error` on both binaries. Only its permission bits were restored afterwards;
  its content hash and the full sandbox manifest were then verified unchanged.
- JSON findings reproduced the text block, stderr was empty, and fail-closed
  sandbox manifests including file modes were identical before and after every
  run. Unchanged sentinels show they were not modified, not that they were not
  read.

## Correction to RH-M10

The RH-M10 receipt says the mode-000 shell's "content was restored and
verified". Only its permission bits were restored; its content was verified
unchanged. The RH-M10 receipt remains as written.

## Limits

Mode bits only: no ACL, ownership, `noexec` mount, capability, setuid or
effective-access check, and no proof that the loader runs. Synthetic fixtures
only. RH-M2-01 and RH-M5-01 remain open; the M1 design remains held.
