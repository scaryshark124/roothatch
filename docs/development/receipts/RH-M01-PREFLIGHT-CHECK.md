# RH-M01 — `roothatch check <dir>` receipt

Date: 2026-10-24. **Functional acceptance of a read-only preflight.** Not a
security PASS, boot/repair capability or release.

## Delivered behavior

- `roothatch check <dir>` inspects a Linux root tree without privileges.
- Checks: `/bin/sh` resolves inside `<dir>` (merged-usr links allowed); it is an
  ELF64 little-endian x86-64 file; its PT_INTERP resolves inside `<dir>` (absolute
  link targets are re-rooted at `<dir>`).
- Findings use stable codes, including `shell_missing`, `interp_missing`,
  `arch_unsupported`, `symlink_escape`, `symlink_loop`, `shell_not_regular`,
  `interp_not_regular`, `elf_invalid` and `read_error`.
- Exit status: 0 limited checks passed, 3 findings, 2 usage error, 1 output failure.
- No target execution, mounts, namespaces, writes or network. Resolution uses
  descriptor-relative `O_PATH|O_NOFOLLOW` lookups, a 40-hop symlink cap and a
  bounded 64 KiB ELF read; a source guard test rejects `os/exec` and
  mount/chroot/namespace calls in production code.

## Executed verification

- Independent functional review: round 1 found a trailing-slash false PASS on a
  non-directory (`sh -> "dash/"`, PT_INTERP ending in `/`); corrected with
  regression fixtures; round 2 approved.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go build`, and `go test -race` for cli/preflight passed.
- The compiled binary ran as a subprocess on all 29 catalog fixtures (healthy
  merged-usr, Debian absolute loader link, missing shell/interpreter, wrong
  architecture, escapes, loops, non-regular files, invalid ELF, trailing-slash
  cases). All 29 gave the expected exit status and finding codes with empty
  stderr, and lstat manifests (paths, modes, content hashes, link targets) were
  identical before and after every run.
- Implementer failing-test-first evidence is author-reported and was not re-run.

## Limits

Linux only; requires `/proc`; a symlinked `<dir>` itself is followed; the
interpreter is checked only for presence and file type. Synthetic fixtures only;
no real installation, privileged or VM qualification is claimed. RH-M2-01 remains
open while the M1 design is held.
