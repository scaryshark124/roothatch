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

Implemented commands are `help`, `version` and `check`. Native entry, doctor,
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
