# Product brief

Status: accepted direction; product functionality is not implemented yet.

## Purpose and primary journey

Build Linux from a debootstrap base or diagnose and repair an existing
installation, then boot-test the result without rebuilding the mount/VM setup.

1. Point Roothatch at an existing installation or fresh debootstrap directory.
2. Inspect identity/layout; ask once when devices or the EFI partition are ambiguous.
3. For a new build, create/import into a managed image-backed workspace with a
   normal directory interface. A directory alone supplies no partition table or ESP.
4. Enter with managed mounts; install packages, kernel, initramfs and GRUB.
5. Exit, release host mounts, and boot through virtual firmware and GRUB.
6. Inspect the real boot result; return to editing, checkpoint or rehearse an upgrade.
   Persistent guest changes require an explicit mode.

## First-release target

Go implementation and Go-first development tooling. Native entry and real VM boot
are both required in the first release, not an eventual VM add-on. No mandatory
Docker daemon or AI service. The first qualified path is Linux/x86-64,
Debian-family debootstrap, UEFI/GRUB and conventional unencrypted storage.

Build AND existing-install repair remain core. The master checklist retains entry,
layout management, VM boot, doctor/explicit repair, checkpoints, upgrade rehearsal,
explicit recipes, resource budgets, interrupted-session recovery and optional
sanitized diagnostics. Slicing work does not redefine a shell demo as a release.

## Required limits

- Discovery is not permission to mount arbitrary disks or network shares.
- Swap is activated, not mounted; native entry does not require host swap changes.
- Chroot uses the host kernel; a VM uses its own guest kernel.
- Direct-kernel boot cannot validate GRUB/EFI; test modes must say what they prove.
- Host and guest must never write the same filesystem concurrently.
- Protect real host firmware variables and unrelated devices.
- A snapshot cannot promise to undo raw-device or firmware writes.
- VM success does not certify every physical driver, firmware or TPM configuration.

## Still to specify

Exact target/workspace schema, mount profiles, privilege/helper boundaries,
VM ownership handoff and readiness contract belong to RH-001. RH-D003 selects the
public repository and Apache-2.0 license. Release toolchain, actual publication
and any third-party Go dependency choices remain open.
