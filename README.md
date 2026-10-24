# Roothatch

**Build it. Fix it. Boot it.**

A Linux build-and-rescue workbench written in Go. The intended workflow joins
filesystem preparation, interactive work, diagnostics, and real VM boot testing.
Docker will not be a mandatory runtime dependency.

## Status

**Pre-alpha.** Only `help` and `version` plus a limited, read-only `check <dir>`
preflight are implemented. `check` reports whether `/bin/sh` and its ELF
interpreter resolve inside `<dir>` as x86-64 ELF without leaving the tree (for
the interpreter, a header-level check of its ELF class, byte order and machine
and that its type is ET_EXEC or ET_DYN, not a verdict that the loader works), and
applies Debian naming-convention consistency checks to the in-tree `/boot`
(`vmlinuz-<version>` with a matching `initrd.img-<version>`, plus the optional
`/vmlinuz` and `/initrd.img` links); a pass does not show the root is bootable or
healthy. `check --json <dir>` writes the same report as one JSON document
(`schema_version` 1, `result` `pass` or `findings`, and `findings` with `code`,
`path` and `detail`); `pass` is not a bootability verdict. There is no working chroot, mount,
bootstrap, repair, image, or VM backend yet.
Do not run this project as root or use it to repair an actual installation.

## The product we are building

- Start with a debootstrap tree or an existing Linux installation.
- Enter through a directory while Roothatch manages the required root, boot,
  EFI and pseudo-filesystem setup, with explicit resolution of ambiguous devices.
- Work interactively, install a kernel and bootloader, then leave the workspace.
- Boot the same managed system in a VM through firmware and the installed
  bootloader, rather than mistaking direct-kernel boot for a bootloader test.
- Diagnose failures, preserve checkpoints and rehearse changes on disposable copies.

Native entry and VM boot are both first-release requirements, not optional future
add-ons. Initial qualification is Linux/x86-64, Debian-family debootstrap, UEFI,
GRUB, and a conventional unencrypted layout. This bounds the first tested path;
it does not delete the larger build-and-repair vision. See the
[product brief](docs/PRODUCT_BRIEF.md) and [architecture](docs/ARCHITECTURE.md).

## Build and verify the current foundation

A local Go 1.24 or newer toolchain is sufficient. There are no third-party Go
dependencies. The toolchain used during bootstrap was Go 1.24.4; the supported
release toolchain must be requalified before public binaries are shipped.

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o ./bin/roothatch ./cmd/roothatch
./bin/roothatch help
./bin/roothatch version
./bin/roothatch check /path/to/linux-root   # read-only; exit 0 pass, 3 findings
```

Repository: https://github.com/scaryshark124/roothatch

Go module: `github.com/scaryshark124/roothatch`. This repository contains the
pre-alpha source foundation; no tagged release or boot/repair-capable binary is
advertised. See the [current checkpoint](docs/development/CURRENT_STATE.md) for
publication and verification status.

## Project navigation

- [Master checklist](MASTER_CHECKLIST.md): stable requirement IDs and completion proof.
- [Current checkpoint](docs/development/CURRENT_STATE.md): actual state and next task.
- [Delivery policy](docs/development/DELIVERY_POLICY.md): roles and acceptance.
- [Verification strategy](docs/development/VERIFICATION.md): unit, runtime and boot proof.
- [Kanban guide](docs/development/KANBAN.md): durable board and task lifecycle.
- [Decisions](docs/decisions/README.md): accepted direction and unresolved choices.
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md).

Source lives in `cmd/` and `internal/`. Design docs describe future components;
empty pretend implementations are intentionally absent. Synthetic fixtures belong
in `testdata/`; real installations, firmware variables, secrets, VM disks and raw
operator logs belong outside the repository.

## License and publication

Copyright 2026 The Roothatch Authors.

Licensed under the **Apache License, Version 2.0 (Apache-2.0)**. See the full
[LICENSE](LICENSE) and [NOTICE](NOTICE). Source publication does not imply a
product release or privileged-runtime qualification. Hosted checks are visible
in [GitHub Actions](https://github.com/scaryshark124/roothatch/actions).
