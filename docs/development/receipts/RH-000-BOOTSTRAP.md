# RH-000 bootstrap receipt

Date: 2026-10-23. **PARTIAL delivery — verified local foundation; instruction binding pending.**

## Delivered locally

- Initialized independent Git source repository on `main`; separate local
  build/cache/evidence/runtime storage outside source Git.
- README, master checklist with stable requirement IDs, accepted product direction,
  architecture, decisions, task template, delivery policy and verification strategy.
- Contributing/security documentation, issue/PR templates and pinned CI definition.
- Native Hermes project and separate `roothatch` board, with held design,
  publication and instruction-binding tasks. No provider-backed worker run.
- Nonprivileged Go help/version CLI. Other commands return usage errors instead
  of pretending to enter, diagnose, build or boot a system.

## Direct verification

Toolchain: Git 2.47.3; Go 1.24.4 linux/amd64. No dependency/package installation.
Go checks used the local toolchain with module proxy/checksum network access off.

- Causal RED: a compiling no-op CLI failed the actual output/exit tests, including
  unsupported commands and output-write failure. This was behavior, not setup error.
- `go test -count=1 -json ./...`: 6 top-level tests plus 13 subtests pass; zero
  failed or skipped test events.
- `go test -count=1 -race -json ./...`: same test set passes; not added to the prior count.
- `gofmt -l cmd internal`: empty output after a formatting-only correction.
- `go vet ./...`: exit 0.
- `go build -trimpath ... ./cmd/roothatch`: exit 0.
- Actual binary help/version: exit 0; version is `Roothatch 0.0.0-dev`.
- Actual unknown command, extra argument, planned enter and planned boot: exit 2,
  empty stdout and explanatory stderr.
- Document checks: required files, relative links, unique checklist IDs and retained
  build/repair/boot and role boundaries.

Raw outputs and the closing source manifest are retained outside the repository.
The initial write interruption and formatting-only check failure are preserved;
neither is represented as a product defect or erased from local history.

## Remaining setup limitation

The protected project `AGENTS.md` write timed out awaiting tool approval and
returned an explicit no-retry/no-alternate-path restriction. It remains absent.
No substitute instruction file/skill, profile modification or worker dispatch was
used. The existing three worker SOUL/config files are byte-unchanged. Functional
and defensive roles are selected/documented, but actual project/profile loading
and first-run qualification remain pending. RH-003 owns this remaining step.

## Git and release state

No staged files, commits, remote, push or release. The local module is temporarily
`roothatch`. Owner will provide the public repository URL and select a license;
no license grant is claimed. CI actions are pinned to observed upstream tag commit
identities, but hosted CI has not run. Public delivery remains RH-002.

No privileged operations, mounts, target images, firmware writes, swap changes,
VM/container starts, private-target access or model/account/permission changes.
No independent functional review or defensive PASS is claimed for the future
product. The next product task is the bounded target/workspace and boot-lifecycle
design, not automatic implementation of the entire checklist.
