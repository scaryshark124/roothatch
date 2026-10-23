# Verification strategy

## Foundation

Run gofmt checks, `go test ./...`, `go test -race ./...`, `go vet ./...` and
`go build -o ./bin/roothatch ./cmd/roothatch`. Exercise the binary's streams and
exit codes for help/version, invalid arguments and unsupported planned commands.
Document tests check required files, relative links, unique checklist IDs and
retained role/scope markers. A CI workflow definition is not hosted execution.

## Causality

Changed behavior needs a test failing for the intended missing/broken behavior,
then passing with implementation. A typo, missing dependency or setup error is
not behavioral RED. Use disposable predecessor or focused mutation tests when
needed; never damage real targets for proof. Preserve failed results.

## Future proof tiers

1. Synthetic/unit filesystem and lifecycle cases.
2. Actual disposable namespace/mount/TTY/process and cleanup witnesses.
3. Disposable images: metadata, target identity, boot/EFI and checkpoints.
4. QEMU firmware -> GRUB -> guest kernel -> target root -> readiness.
5. End-to-end build and existing-install repair journeys on disposable targets.
6. Separately authorized physical-hardware qualification, never inferred from a VM.

Do not replace required runtime proof with mocks. Label unavailable proof honestly.
A started VM process is not successful guest boot.

## Required negatives

Wrong/ambiguous device, stale UUID, unsupported architecture/layout, redirected
paths/symlinks, missing loader/kernel/initramfs, host/guest write conflicts,
interrupted mount setup, child/VM death, stale resource ownership, unrelated-mount
preservation, read-only target preservation, unchanged host swap/NVRAM and
synthetic secrets absent from diagnostics. Bind each to its implementation task.

## Evidence

Bind commands, tool versions, results and candidate hashes. Raw host-specific
logs stay in a separate local artifact root; source receipts are sanitized.
Independent functional reviewers do not repair their candidates. Defensive
checkpoints are separately scoped. Parent checks actual artifacts and reproduces
critical tests. Scaffold tests do not prove the future chroot/VM product.
