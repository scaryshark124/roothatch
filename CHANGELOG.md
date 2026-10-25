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
- `check` now also reports a `/boot/initrd.img-<version>` link that leaves the
  root as `symlink_escape` at that initrd path, immediately before the
  unchanged `initrd_missing` for the same version. The initrd is never
  followed and the kernel stays counted.
- `check` now reads the ELF header of a regular in-root interpreter through the
  same pinned descriptor: a non-ELF, malformed-ident or truncated header is
  `interp_elf_invalid`, and a valid header that is not ELF64 little-endian
  x86-64 is `interp_arch_unsupported`, both at the PT_INTERP path. An
  unreadable interpreter is now `read_error`. This is a header-level check
  only, not a verdict that the loader works.
- `check` now also requires the interpreter's ELF64 little-endian x86-64
  header to declare type ET_EXEC or ET_DYN; any other `e_type` (for example
  ET_REL, ET_NONE or ET_CORE) is `interp_elf_invalid` at the PT_INTERP path,
  naming the type. Malformed headers and unsupported architectures keep their
  earlier findings. Program headers are still not inspected.
- `check` now reports `shell_not_executable` at `/bin/sh` when the resolved
  regular shell is a valid ELF64 little-endian x86-64 file but its mode has no
  owner, group or other execute bit. This reads mode bits only; it is not a
  check of whether any user can run it. The finding does not stop the check: a
  static shell is still recognized, and a dynamic shell's interpreter checks
  still run and report after it. Earlier shell failures keep their single
  finding, and an unreadable shell is still `read_error`. The interpreter's
  permission bits are not checked.
- `check` now reports `interp_not_executable` at the PT_INTERP path when the
  interpreter resolves inside the root to a regular file whose ELF header
  passes but whose own mode (the resolved target's, never a link's or the
  shell's) has no owner, group or other execute bit. This replaces the note
  above that the interpreter's permission bits are not checked. It reads mode
  bits already obtained for that file only; it is not a check of whether any
  user can run it. A non-executable shell and interpreter report
  `shell_not_executable` then `interp_not_executable`. Unreadable interpreters
  keep `read_error`, header failures keep their single finding, and static
  shells still do no interpreter work.
- Added `roothatch check --json <dir>`: the same report as one JSON document
  (`schema_version` 1, `result` `pass`/`findings`, `findings` of
  `code`/`path`/`detail`, `[]` when empty), with unchanged exit codes. Usage
  errors write nothing to stdout. `pass` is not a bootability verdict.
- Added `roothatch check --shell-only <dir>` (also with `--json`, before or
  after `--shell-only`, both before `<dir>`, each at most once) for trees
  without boot files. It runs only the existing `/bin/sh` and ELF interpreter
  checks with the same findings and exit codes; the independent `/boot`
  kernel/initrd and `/vmlinuz`/`/initrd.img` checks are not run, although
  `/bin/sh` or its PT_INTERP may still resolve beneath `/boot`. Its PASS line
  says those boot files were not checked, and its schema_version 1 JSON
  `result` covers only the checks requested. Default `check` output is
  unchanged.
- `check` now accepts `--` to end its options:
  `roothatch check [--json] [--shell-only] -- <dir>`. Only `--json` and
  `--shell-only` may precede the first `--` (each at most once, either order),
  and exactly one argument must follow it; that argument is the directory,
  taken literally, so `check -- --json` checks a directory named `--json` in
  text mode and `check -- --shell-only` runs the full check on a directory
  named `--shell-only`. Forms without `--` keep their previous behavior and
  messages. Compatibility change: bare `check --` and `check --json --`
  previously checked a directory named `--` and are now usage errors (exit 2);
  use `check -- --` or `check ./--` instead.

- Selected Apache-2.0, included LICENSE/NOTICE and bound the actual GitHub module.
- Approved project guidance and Roothatch-specific role bindings; verified native
  root/nested context loading and invalidation/reload with unchanged configuration.

No chroot, mount, repair, bootstrap, image, checkpoint or VM capability is released. This is a source foundation, not a product release.
