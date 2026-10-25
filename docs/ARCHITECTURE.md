# Architecture direction

Only `cmd/roothatch`, `internal/cli` and the read-only `internal/preflight` checker
are executable code so far. The checker inspects `/bin/sh` (including whether any
execute permission bit is set on the resolved file, from mode bits only), the ELF header of its
interpreter (class, byte order, machine and ET_EXEC/ET_DYN type only, then whether any
execute permission bit is set on the resolved interpreter file, again from mode bits only) and, by Debian naming
convention only, the in-tree `/boot` kernels/initrds and optional
`/vmlinuz`/`/initrd.img` links, all through descriptor-confined
resolution; it does not establish bootability. `internal/cli` renders that one
report as text or, for `check --json <dir>`, as a schema_version 1 JSON document.
The following are proposed component boundaries, not delivered implementations.

## One target, two execution modes

The Go CLI coordinates a common target/workspace. Native entry manages Linux
namespaces, mounts and a shell. VM mode controls QEMU and virtual firmware.
Shared ownership and recovery state arbitrate disk access between them.

Planned components:
- `target`: identity, layout inspection, validation and explicit selection.
- `workspace`: managed images, exclusive ownership and recovery states.
- `enter`: mount profiles, terminal/process lifecycle and cleanup.
- `bootstrap`: debootstrap adapter/import, not a replacement for apt.
- `bootloader`: target-only GRUB/EFI preparation and artifact checks.
- `vm`: QEMU/QMP, firmware state, overlays, limits and boot readiness.
- `doctor`: supported checks and explainable findings.
- `checkpoint`: storage-specific snapshot/copy semantics.

Go owns orchestration; existing Linux utilities, debootstrap, QEMU and firmware
can remain dependencies of the corresponding features. No hypervisor rewrite or
zero-dependency promise for the completed product.

## Storage and isolation

Managed images expose a directory for editing and release it before guest use.
Imports must preserve required metadata. An existing physical installation is
never automatically handed writable to QEMU. Rehearsal uses a qualified copy or
snapshot with a stable backing base. Unsupported targets fail before mutation.

Design must close target identity, lock ownership, stale-session recovery, mount
provenance, child shutdown, crash handling and cleanup ordering. Clean only owned
resources; preserve original DNS bytes/symlink meaning. Device and firmware
exposure must be selected, not a blanket bind of host state.

## Boot proof

Firmware -> GRUB -> kernel -> initramfs -> target root -> readiness is the normal
acceptance chain. Direct-kernel debug is distinct. QEMU alive is not guest ready.
Firmware variables belong to the VM workspace, not host NVRAM. Disposable tests
must prove original preservation; persistent VM use is explicit.

## Next contract

RH-001 specifies supported inputs/layouts, observable lifecycle, errors, write
ownership and test fixtures. A bounded defensive design checkpoint precedes
privileged implementation. This document itself authorizes no runtime effects.
