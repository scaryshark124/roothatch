# Changelog

## Unreleased

- Established product documentation, delivery policy and verification checklist.
- Added a nonprivileged help/version CLI foundation and tests.
- Added a Go-based local/hosted verification workflow definition.
- Added `roothatch check <dir>`: unprivileged, read-only preflight for `/bin/sh`,
  its x86-64 ELF architecture and its interpreter, with symlink containment.
  Exit 0 limited checks passed, 3 findings, 2 usage error, 1 output failure.
- `check` also applies read-only Debian naming-convention consistency checks to
  the in-tree `/boot`: at least one `vmlinuz-<version>` regular file
  (`kernel_missing`), a matching `initrd.img-<version>` per kernel
  (`initrd_missing`), and optional `/vmlinuz` and `/initrd.img` links that must
  resolve inside the root to regular files (`boot_link_broken`,
  `symlink_escape`). Kernel and initrd contents are not read; separate /boot or
  EFI partitions and bootloader configuration are not checked.
- `check` now reports a `/boot/vmlinuz-<version>` candidate whose link leaves
  the root as `symlink_escape` at that candidate path instead of skipping it
  silently. It is still never followed or counted as a kernel; `kernel_missing`
  is still reported when no valid kernel remains. Escaping initrds are still
  reported as `initrd_missing`.
- Added `roothatch check --json <dir>`: the same report as one JSON document
  (`schema_version` 1, `result` `pass`/`findings`, `findings` of
  `code`/`path`/`detail`, `[]` when empty), with unchanged exit codes. Usage
  errors write nothing to stdout. `pass` is not a bootability verdict.

- Selected Apache-2.0, included LICENSE/NOTICE and bound the actual GitHub module.
- Approved project guidance and Roothatch-specific role bindings; verified native
  root/nested context loading and invalidation/reload with unchanged configuration.

No chroot, mount, repair, bootstrap, image, checkpoint or VM capability is released. This is a source foundation, not a product release.
