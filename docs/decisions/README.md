# Decisions

Accepted product direction is separate from execution authority. Ironclad's
private decisions and milestone gates do not govern this independent project.

## RH-D001 — Identity and direction — ACCEPTED, 2026-10-23

Owner selected **Roothatch — Build it. Fix it. Boot it.** Go implementation and
Go-first tooling. Build-from-debootstrap and Linux repair are both core. Native
entry and real VM boot belong in the first release. Automate required mounts,
resolve ambiguous target identity explicitly, and require no Docker daemon.
First qualification: x86-64 Debian-family UEFI/GRUB, conventional unencrypted
layout. Wider support remains tracked rather than claimed.

Provenance: owner discussion and explicit name/direction acceptance. Private
message identifiers remain in the local bootstrap record, not public Git.

## RH-D002 — Foundation and roles — ACCEPTED, 2026-10-23

Owner requested project directory, Git initialization, README/master checklist,
dedicated native board/project, and reuse of ironcladexec, ironcladreview and
ironcladsecurity with adapted delivery discipline. Parent owns bootstrap;
functional and defensive verdicts remain separate. Owner will create public GitHub.

The setup grant does not select a license, authorize publication, permit real-disk
operations or start autonomous roadmap execution. Existing model/account/tool
settings stay unchanged. Operational role binding needs actual verified loading,
not merely naming profiles in documentation.

## RH-D003 — Repository, license and setup resumption — ACCEPTED, 2026-10-23

Owner created https://github.com/scaryshark124/roothatch, selected Apache-2.0 and
requested normal resubmission of the protected instruction setup. The exact
previously held AGENTS.md write succeeded through its normal consent route.
Existing selected role profiles receive Roothatch-specific bindings without
changing their model/account/tool settings or the meaning of Ironclad assignments.

Local module identity is `github.com/scaryshark124/roothatch`; origin uses the
matching HTTPS repository URL. LICENSE contains canonical Apache-2.0 text;
NOTICE uses The Roothatch Authors. These choices resolve RH-O001/RH-O002.
Initial commit/source publication, hosted CI and public binaries remain separate;
no worker or privileged product execution is authorized by these setup choices.

## RH-D004 — Initial public publication and identity — ACCEPTED, 2026-10-23

Owner approved the initial scaffold commit/push to this repository's `main`
branch using GitHub identity `scaryshark124` and the account's noreply email.
Authenticated account metadata and GitHub's documented format resolve it to
`158119705+scaryshark124@users.noreply.github.com`. Both author and committer use
this project-local identity; other repositories and global settings are unchanged.

Scope includes exact selected source publication, remote readback, fresh-clone
verification, hosted CI and ordinary publication-documentation closure. No force
push, tag/release, new credentials/settings, worker dispatch or privileged product
execution is implied. Historical setup receipts retain their former pending state;
the current checkpoint and publication receipt control the live delivery status.

## Open choices

RH-O001 (repository/module) and RH-O002 (license) are resolved by RH-D003.
Remaining choices:
- **RH-O003:** RH-001 exact target/workspace/privilege/boot-lifecycle contract.
- **RH-O004:** Public vulnerability-reporting channel before release.
- **RH-O005:** Release toolchain and any third-party Go dependencies.

Record later decisions with date, scope, provenance, superseded choices and
remaining effects. Do not convert proposals to acceptance silently.
