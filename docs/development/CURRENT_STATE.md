# Current delivery state

Date: 2026-10-24

## Actual state

M0 project foundation is COMPLETE and public: initial commit
`7716893bc28e6d1af0023f923fbf21b7e9d021df` on `main`, Apache-2.0, fresh-clone and
hosted CI verification. See the [publication receipt](receipts/RH-002-PUBLICATION.md).

RH-M01 delivers `roothatch check <dir>`, an unprivileged, read-only preflight. It
reports whether `/bin/sh` resolves inside `<dir>`, is ELF64 little-endian x86-64,
and whether its ELF interpreter resolves inside `<dir>`. Symlinks are resolved
component by component against `<dir>` and are never followed out of it. Exit
status: 0 limited checks passed, 3 findings, 2 usage error, 1 output failure. It
runs no target code, mounts nothing and writes nothing. Proof: independent
functional review (one correction round) and parent acceptance of the compiled
binary on 29 synthetic fixtures; see the [RH-M01 receipt](receipts/RH-M01-PREFLIGHT-CHECK.md).
This is functional acceptance only, not a security PASS. Known limits: Linux only,
requires `/proc`, a symlinked `<dir>` itself is followed, and the interpreter is
checked only for presence and file type.

RH-M04 extends `check` with read-only Debian naming-convention consistency checks
on the in-tree `/boot`: at least one `vmlinuz-<version>` regular file
(`kernel_missing`), a matching `initrd.img-<version>` for each kernel
(`initrd_missing`), and optional `/vmlinuz` and `/initrd.img` links that, when
present, must resolve inside the root to regular files (`boot_link_broken`,
`symlink_escape`). Missing shortcut links are not a finding. Boot checks run even
when shell checks fail. `/boot` is enumerated only through the confined directory
descriptor with a 4096-entry cap. Kernel/initrd contents, bootloader
configuration and separate boot/EFI partitions are not checked, and a finding is
not a bootability verdict. Proof: independent functional review (round 1 PASS)
and parent acceptance of the compiled binary on 54 synthetic fixtures with exact
finding-code matching and unchanged trees; see the
[RH-M04 receipt](receipts/RH-M04-BOOT-CHECK.md). Functional acceptance only, not a
security PASS.

RH-M05 adds `roothatch check --json <dir>`: the same report as text mode,
serialized as one JSON document `{"schema_version": 1, "result": "pass" |
"findings", "findings": [{"code", "path", "detail"}]}` with `[]` on a pass and
the existing sanitized path/detail strings. Exit codes are unchanged; usage
errors exit 2 with empty stdout. Plain `check <dir>` output is byte-for-byte
unchanged. `"pass"` means only that the current limited checks passed. Proof:
independent functional review (round 1 PASS) and parent acceptance of the
compiled binary on 60 synthetic fixtures, comparing text output with the
previous release; see the [RH-M05 receipt](receipts/RH-M05-CHECK-JSON.md).

Implemented commands are `help`, `version` and `check` (with `--json`). Native entry, doctor,
bootstrap, storage and VM functionality are not delivered. RH-M2-01 stays
unchecked: `check` covers its synthetic-root diagnostics, but the row remains open
while the M1 target/lifecycle design is held.

## Next action and remaining boundaries

Work proceeds only inside owner-approved bounded milestones (RH-D005); the next
milestone needs explicit owner approval. RH-001 remains owner-paused and held for
the bounded target/workspace and edit-to-boot design; retain real VM integration
in the first release. No automatic worker assignment, privileged implementation,
package installation or real-target operation follows. A separately scoped
defensive design checkpoint precedes privileged implementation.

Do not request the license, repository URL or initial publication approval again;
RH-D003/RH-D004 are fulfilled.

## Navigation and historical records

[Master checklist](../../MASTER_CHECKLIST.md), [decisions](../decisions/README.md),
[delivery policy](DELIVERY_POLICY.md), [verification](VERIFICATION.md),
[Kanban](KANBAN.md), [setup receipt](receipts/RH-002-003-SETUP.md).
The [original bootstrap receipt](receipts/RH-000-BOOTSTRAP.md) and timeout are
immutable historical snapshots. Their old pending license/instruction state is
superseded by RH-D003 and the current setup receipt, not a new request to repeat
already completed choices or protected writes.
