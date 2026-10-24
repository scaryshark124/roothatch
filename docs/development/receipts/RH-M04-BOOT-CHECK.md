# RH-M04 — in-tree `/boot` checks receipt

Date: 2026-10-24. **Functional acceptance of read-only boot-file consistency
checks.** Not a security PASS, bootability verdict, boot/repair capability or
release.

## Delivered behavior

- `roothatch check <dir>` also inspects the in-tree `/boot`, Debian naming only:
  - no `vmlinuz-<version>` regular file (nonempty version) -> `kernel_missing`;
    a missing or non-directory `/boot` is reported the same way;
  - each kernel without a matching `initrd.img-<version>` regular file ->
    one `initrd_missing` naming that version;
  - optional `/vmlinuz` and `/initrd.img`: absent is not a finding; present but
    dangling, looping, non-regular or trailing-slash-after-file ->
    `boot_link_broken`; leaving the root -> `symlink_escape`;
  - a `/boot` symlink leaving the root -> `symlink_escape`, never followed.
- Boot checks run independently of the shell/interpreter checks; all findings
  are reported. Exit status is unchanged (0 / 3 / 2 / 1).
- `/boot` is enumerated only through the descriptor returned by the confined
  resolver, verified by device/inode, with a 4096-entry cap; read errors or
  overflow are findings, never a pass. Kernel/initrd contents are not read.

## Executed verification

- Independent functional review: round 1 PASS, no material findings.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed.
- The compiled binary ran as a subprocess on all 54 catalog fixtures (29 earlier
  fixtures with a valid boot layout added and unchanged expectations, plus 25
  boot fixtures). Every fixture gave the expected exit status, exactly the
  expected multiset of finding codes, a consistent PASS/FAIL line and empty
  stderr, with lstat manifests (paths, modes, content hashes, link targets)
  identical before and after.
- A durable test (`cmd/roothatch/main_test.go`) now builds and runs the real
  binary against the full catalog in normal CI.
- Implementer failing-test-first evidence is author-reported and was not re-run.

## Limits

Debian naming convention only; no separate boot/EFI partition, fstab, bootloader
configuration, initramfs content or kernel format checks. A kernel candidate that
escapes the root is not counted rather than reported as an escape. Synthetic
fixtures only; no real installation, privileged or VM qualification is claimed.
RH-M2-01 and RH-M5-01 remain open; the M1 design remains held.
