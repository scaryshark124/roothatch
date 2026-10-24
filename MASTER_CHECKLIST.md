# Roothatch master checklist

Current position: **M0 COMPLETE; read-only `check <dir>` preflight delivered (RH-M01); M1 design is held and M1 onward is not complete.**
Completed foundation rows are backed by the historical
[RH-000 receipt](docs/development/receipts/RH-000-BOOTSTRAP.md), subsequent
[RH-002/003 setup receipt](docs/development/receipts/RH-002-003-SETUP.md), and
[verified initial publication](docs/development/receipts/RH-002-PUBLICATION.md).
M0 completion is not a boot/repair-capable release.
See [current state](docs/development/CURRENT_STATE.md) for the next action.

This is the requirement inventory, not a percentage score. Check a row only with
observable acceptance and linked proof. Stages are conjunctive: partial success
does not close an aggregate. Exec = ironcladexec, review = ironcladreview,
security = ironcladsecurity. Kanban owns task/run history; this file owns product
obligations. The owner-selected first release includes the complete build/repair/
boot workflow; a shell-only demo is not that release.

## M0 — Foundation

- [x] **RH-M0-01** Local source repository and separate private/runtime storage. Owner: parent. Proof: main branch, exact root, ignore probes and manifest.
- [x] **RH-M0-02** README, scope, architecture, decisions, task template and checkpoint. Owner: parent. Proof: local links, unique requirements and truthful capability status.
- [x] **RH-M0-03** Runnable nonprivileged help/version CLI. Owner: parent bootstrap. Proof: attributable RED, unit/race tests, gofmt/vet/build and actual binary exit/output checks.
- [x] **RH-M0-04** Dedicated native project/board and held follow-up cards. Owner: parent. Proof: exact board/project/workspace, no accidental worker runs, notification routing.
- [x] **RH-M0-05** Three worker roles bound to Roothatch. Owner: parent. Proof: approved instructions, root/nested native loading and invalidation/reload, unchanged model/account/tool configurations. Component loading is verified; no live worker run or future model-compliance claim.
- [x] **RH-M0-06** Public repository URL, final Go module path, Apache-2.0 license and committed baseline. Owner: owner/parent. Proof: RH-D003/RH-D004, initial commit 7716893bc28e6d1af0023f923fbf21b7e9d021df and GitHub identity/license readback.
- [x] **RH-M0-07** Initial public delivery and hosted CI. Owner: parent. Proof: exact remote SHA, independent fresh-clone tests/build and successful hosted Go foundation run 39958969567. Parent bootstrap review; no independent product/security verdict claimed.

## M1 — Target and edit-to-boot design

- [ ] **RH-M1-01** Target/lifecycle contract for existing installation, fresh directory and managed image. Owner: exec/review. Proof: concrete states, inputs/errors and accepted bounded brief.
- [ ] **RH-M1-02** Root, separate boot and EFI layout discovery; ambiguous identity asks rather than guesses. Owner: exec/review. Proof: synthetic layouts, stale UUIDs, conflicts and rejected unsupported layouts.
- [ ] **RH-M1-03** Mount ownership, host/guest write exclusion, cleanup and crash recovery design. Owner: exec/review. Proof: state and interruption matrix.
- [ ] **RH-M1-04** Defensive design checkpoint before privileged implementation. Owner: security. Proof: scoped findings/disposition for paths, devices, target identity, EFI and VM storage; not a whole-host audit.

## M2 — Enter correctly

- [ ] **RH-M2-01** Nonmutating preflight with missing shell/loader/architecture diagnostics. Owner: exec/review. Proof: healthy and invalid synthetic roots.
  Partial: synthetic-root `check` delivered and verified ([RH-M01 receipt](docs/development/receipts/RH-M01-PREFLIGHT-CHECK.md)); the row stays open while the M1 target/lifecycle design is held.
- [ ] **RH-M2-02** Private mount namespace and managed proc/sys/dev/pts/run/DNS profiles. Owner: exec/review. Proof: real disposable runtime witnesses and original DNS preservation.
- [ ] **RH-M2-03** Interactive terminal, signals, descendant lifecycle and exit-code propagation. Owner: exec/review. Proof: actual PTY/subprocess and interruption tests.
- [ ] **RH-M2-04** Required boot/EFI mounts, no blind fstab mounting, host swap unchanged. Owner: exec/review. Proof: explicit selections, rejected ambiguity and unchanged-host witnesses.
- [ ] **RH-M2-05** Interrupted sessions recover and clean only owned resources. Owner: exec/review. Proof: abrupt death, stale ownership and retained pre-existing mounts/data.
- [ ] **RH-M2-06** Defensive implementation checkpoint before real-target use. Owner: security. Proof: affected-boundary findings/disposition; disposable success does not authorize real disks.

## M3 — Build from a base system

- [ ] **RH-M3-01** debootstrap adapter/import. Owner: exec/review. Proof: actual disposable Debian base and required metadata preservation, not fabricated bootstrap output.
- [ ] **RH-M3-02** Image-backed workspace exposing a directory; root and ESP plus declared optional boot/swap layout. Owner: exec/review. Proof: real image layout and entry into that same image.
- [ ] **RH-M3-03** Interactive package/kernel installation and explicit repeatable recipes. Owner: exec/review. Proof: installed artifacts and rerun/failure behavior; arbitrary shell history is not a recipe.
- [ ] **RH-M3-04** Target-only GRUB/UEFI preparation. Owner: exec/review/security. Proof: ESP/config/kernel/initramfs checks and unchanged host NVRAM.

## M4 — Real VM boot, required in first release

- [ ] **RH-M4-01** QEMU/virtual UEFI lifecycle and accelerator preflight. Owner: exec/review. Proof: real process/QMP, limits, cleanup and honest unavailable/slow-mode results.
- [ ] **RH-M4-02** Firmware -> GRUB -> kernel -> initramfs -> target root -> readiness. Owner: exec/review. Proof: actual full-chain boot; direct-kernel launch cannot close this row.
- [ ] **RH-M4-03** Disposable boot with stable base and no concurrent host/guest writers. Owner: exec/review. Proof: unchanged original, overlay effects, conflicts and cancellation.
- [ ] **RH-M4-04** Explicit persistent guest session and return to directory editing. Owner: exec/review. Proof: retained guest change after shutdown, rejected concurrent entry.
- [ ] **RH-M4-05** Separate VM firmware state and optional direct-kernel debug. Owner: exec/review. Proof: firmware isolation and explicit bootloader-test nonclaim for direct boot.
- [ ] **RH-M4-06** Stage-aware failure, panic, timeout and readiness reporting. Owner: exec/review. Proof: seeded and real failures; QEMU alive is not a boot PASS.

## M5 — Repair and recovery capabilities

- [ ] **RH-M5-01** Read-only doctor for boot artifacts, references, package state and available previous-boot logs. Owner: exec/review. Proof: seeded faults, explained findings and unchanged targets.
- [ ] **RH-M5-02** Explicit repair actions, not automatic repair-everything. Owner: exec/review. Proof: selected effect, before/after checks and recovery path.
- [ ] **RH-M5-03** Named snapshot/copy checkpoints with honest storage limits. Owner: exec/review. Proof: actual restore; no raw-device/firmware rollback promise.
- [ ] **RH-M5-04** Upgrade rehearsal in a disposable copy, reboot and compare. Owner: exec/review. Proof: good/bad upgrade cases, preserved original and actual second boot.
- [ ] **RH-M5-05** Build CPU/memory budgets and recoverable session inventory. Owner: exec/review. Proof: enforced limits, interruption and ownership recovery.
- [ ] **RH-M5-06** Optional sanitized diagnostics and opt-in session recording. Owner: exec/review/security. Proof: synthetic secret exclusions and recording off by default.

## M6 — Release qualification

- [ ] **RH-M6-01** Complete build/GRUB/firmware-boot and existing-install repair/boot journeys. Owner: review/parent. Proof: independent end-to-end disposable witnesses, not summed unit counts.
- [ ] **RH-M6-02** Supported distro/storage/toolchain matrix and recovery docs. Owner: exec/review. Proof: tested exact versions, limits and prerequisite errors.
- [ ] **RH-M6-03** Scoped defensive release checkpoint. Owner: security/parent. Proof: disposition of material privileged/import/VM/public-artifact findings.
- [ ] **RH-M6-04** License/notices, repeatable release recipe, checksums and reporting channel. Owner: owner/parent/review. Proof: built/rebuilt artifacts, inspected archive and publication grant.
- [ ] **RH-M6-05** Owner acceptance of first release and hardware/firmware limitations. Owner: owner. Proof: explicit acceptance; VM success is not all-machine assurance.

## Later qualification

- [ ] **RH-X-01** LUKS, LVM, RAID and advanced filesystem layouts. Proof: separately accepted scope and storage-specific runtime witnesses.
- [ ] **RH-X-02** More distributions, architectures and legacy BIOS. Proof: explicit tested support; no emulation-performance promise.
- [ ] **RH-X-03** Secure Boot/signing and TPM-bound workflows. Proof: separately admitted keys/firmware and recovery validation.

## Proof references

Use [verification strategy](docs/development/VERIFICATION.md). Portable sanitized
receipts belong under `docs/development/receipts/`; raw host-specific artifacts
stay outside Git. A pending proof stays unchecked even when code exists.
