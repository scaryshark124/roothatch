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
checked only for presence and file type (superseded by RH-M08 below).

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

RH-M06 makes an existing containment refusal visible: a `/boot/vmlinuz-<version>`
candidate whose link leads outside the root, which the resolver already refused
to follow, is now reported as `symlink_escape` at that candidate path, even when
another valid kernel/initrd pair exists. The candidate is still not counted and
gets no initrd check; with no valid kernel, the existing `kernel_missing` is also
reported unchanged. Escaping initrds and other kernel failures keep their earlier
behavior. Proof: independent functional review (round 1 PASS) and parent
comparison of the previous and new binaries on 63 synthetic fixtures, where only
the three escaping-kernel fixtures changed; see the
[RH-M06 receipt](receipts/RH-M06-KERNEL-ESCAPE.md).

RH-M07 does the same for initrds: when a valid kernel's matching
`/boot/initrd.img-<version>` link leads outside the root, `check` now reports
`symlink_escape` at that initrd path immediately before the unchanged
`initrd_missing` for that version. The initrd is never followed and the kernel is
still counted. This replaces the RH-M06 statement that escaping initrds keep their
earlier behavior. Proof: independent functional review (round 1 PASS) and parent
comparison of the previous and new binaries on 67 synthetic fixtures, where only
the three escaping-initrd fixtures changed and removing the added findings
reproduced the previous output's findings exactly; see the
[RH-M07 receipt](receipts/RH-M07-INITRD-ESCAPE.md).

RH-M08 checks the ELF interpreter's header. After `/bin/sh`'s PT_INTERP resolves
inside the root to a regular file, `check` reads it through the existing pinned,
bounded reader and examines only ELF identification, the class-specific header
length and `e_machine` in the declared byte order. Malformed or truncated headers
report `interp_elf_invalid`; complete headers that are not ELF64 little-endian
x86-64 report `interp_arch_unsupported`; an unreadable interpreter now reports
`read_error` instead of passing silently. This is a header-level check, not proof
that the loader works. Proof: independent functional review (round 1 PASS) and
parent comparison of the previous and new binaries on the same 80 updated
synthetic fixtures, where only the ten new failing interpreter fixtures changed,
plus an unprivileged unreadable-interpreter run; see the
[RH-M08 receipt](receipts/RH-M08-INTERP-HEADER.md).

RH-M09 adds the interpreter's ELF file type to that header check: after the
header is confirmed to be complete ELF64 little-endian x86-64, `e_type` must be
`ET_EXEC` or `ET_DYN`; any other type reports `interp_elf_invalid` at the
interpreter path naming the type. No new reads are made. Malformed and
non-x86-64 headers keep their earlier findings. Proof: independent functional
review (round 1 PASS) and parent comparison of the previous and new binaries on
the same 86 synthetic fixtures, where only the four type-rejection
fixtures changed; see the [RH-M09 receipt](receipts/RH-M09-INTERP-TYPE.md).

RH-M10 reports a `/bin/sh` with no execute permission bits: after the shell
resolves inside the root to a regular file and passes the ELF checks, a mode with
no owner, group or other execute bit reports `shell_not_executable` at `/bin/sh`.
The scan continues, so a dynamic shell's interpreter checks still run. This is a
mode-bit diagnostic only, not an ACL, ownership, `noexec` or effective-access
check. Proof: independent functional review (round 1 PASS) and parent comparison
of the previous and new binaries on the same 92 synthetic fixtures,
where only the three non-executable-shell fixtures changed; see the
[RH-M10 receipt](receipts/RH-M10-SHELL-EXEC.md).

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
