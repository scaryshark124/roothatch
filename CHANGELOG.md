# Changelog

## Unreleased

- Established product documentation, delivery policy and verification checklist.
- Added a nonprivileged help/version CLI foundation and tests.
- Added a Go-based local/hosted verification workflow definition.
- Added `roothatch check <dir>`: unprivileged, read-only preflight for `/bin/sh`,
  its x86-64 ELF architecture and its interpreter, with symlink containment.
  Exit 0 limited checks passed, 3 findings, 2 usage error, 1 output failure.

- Selected Apache-2.0, included LICENSE/NOTICE and bound the actual GitHub module.
- Approved project guidance and Roothatch-specific role bindings; verified native
  root/nested context loading and invalidation/reload with unchanged configuration.

No chroot, mount, repair, bootstrap, image, checkpoint or VM capability is released. This is a source foundation, not a product release.
