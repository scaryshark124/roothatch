# RH-002/003 setup receipt

Date: 2026-10-23. Scope: local license/repository identity and instruction binding.

## Owner-selected setup

- Apache License 2.0 selected; canonical LICENSE and a Roothatch Authors NOTICE added.
- Repository: https://github.com/scaryshark124/roothatch.
- Module/imports and local HTTPS origin use that actual repository identity.
- Exact previously held AGENTS.md bytes resubmitted successfully through write_file
  after the owner's request. Historical timeout preserved, not bypassed.
- Roothatch-specific addenda applied through normal protected-file tools to the
  three selected worker roles. Original Ironclad role bytes remain recoverable
  exactly by removing the bounded addenda; configurations are byte-unchanged.

## Instruction-loading proof — PASS

Installed Hermes identity/project-context components load each actual profile's
role and the correct project AGENTS.md at repository root and nested cmd directory.
Native cache invalidation and subsequent reload retain both. These are component
checks, not full agent startup, a live conversation refresh or future compliance.

The inert probe excludes network and private credential/session files. One
optional .env read was intercepted before contents were read; no credential or
provider access was performed. Existing-home initialization was memoized to avoid
configuration/permission changes. No scanner or policy control was disabled.
No worker or provider-backed review was launched.

## License/source verification

LICENSE is byte-identical to the Apache project's published text and the Debian
common-license copy: 11,358 bytes, SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
Source: https://www.apache.org/licenses/LICENSE-2.0.txt.
The appendix's example placeholders remain unchanged in the canonical text;
project attribution is supplied separately in NOTICE and README.

The README test marker now checks Apache-2.0 rather than the superseded
license-undecided statement. Required-document tests include AGENTS.md, LICENSE
and NOTICE. A new exact-license/module-identity check protects those choices.
Final Go verification: 7 top-level tests plus 13 subtests pass in both ordinary
and race suites, with no failing or skipped tests. The command package has no
unit-test files (a package-level skip event), and its compiled binary was exercised
separately. Formatting, vet and build pass. Actual help/version exit 0; unsupported
enter/boot exit 2. Counts overlap across runs and are not added together.

Causal checks in a disposable copy passed for the real source, failed on the
specific assertions after changing LICENSE or restoring the old module identity,
and passed again after restoration. The owned copy was removed; source unchanged.

## Effects and nonclaims

No staging, commit, push, release, hosted CI, privileged target operation or worker
launch. First public author identity remains unexposed; no silent author change.
Initial commit/source publication stays on RH-002; RH-001 design remains held.
No defensive checkpoint or chroot/VM functionality is claimed from setup.
Original RH-000 partial receipt and timeout remain historical snapshots; the
current checkpoint supplies today's state rather than rewriting that history.
