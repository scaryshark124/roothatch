# RH-002 — Initial public publication receipt

Date: 2026-10-23. **Initial source publication verified.** This is a project
foundation, not a boot/repair-capable product release.

## Published identity and source

- Repository: https://github.com/scaryshark124/roothatch
- Branch: `main`; initial remote was empty; normal non-force push.
- Initial commit: `7716893bc28e6d1af0023f923fbf21b7e9d021df`.
- Initial tree: `afac4d5685ce807bc0cc657f782c66733f870982`.
- Initial content: 29 source/documentation files, 66,687 bytes.
- Author and committer: `scaryshark124 <158119705+scaryshark124@users.noreply.github.com>`.
- GitHub's commit API associates both identities with `scaryshark124`.
- Identity is repository-local; no global identity or credential settings changed.

[Initial commit](https://github.com/scaryshark124/roothatch/commit/7716893bc28e6d1af0023f923fbf21b7e9d021df)

GitHub recognizes the repository's license as **Apache-2.0**. The published LICENSE
is the canonical 11,358-byte text with SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
NOTICE identifies The Roothatch Authors. No private name/email was added to the
commit identity or public source.

## Executed verification

- Parent-reviewed exact selected file set, executable entry points and documentation.
- Exact staged blobs matched the source manifest; staged whitespace check passed.
- Gitleaks 8.30.1 scanned the selected source and reachable initial history with
  redacted output: zero findings. Targeted personal-metadata/path checks also passed.
  These are bounded scans, not exhaustive assurance.
- Go unit and race suites each passed 7 top-level tests plus 13 subtests; zero
  failing or skipped tests. Counts overlap and are not summed.
- Formatting, vet, build and actual help/version/unsupported-command checks passed.
- Remote `main` matched the exact initial commit; local worktree was clean.
- A fresh HTTPS clone on a different filesystem reproduced all 29 files/hashes,
  passed strict Git integrity, and passed unit/race/vet/build/binary checks using
  fresh Go caches. No local object alternates or source-checkout build inputs.
- Disposable restore workspace was removed after verification.

## Hosted CI — PASS

Workflow: **Go foundation**. Push run `39958969567`, bound to the initial commit,
completed successfully. Its verify job executed formatting, race tests, vet,
build and the compiled version command; none of those steps was skipped.

[Verified initial CI run](https://github.com/scaryshark124/roothatch/actions/runs/39958969567)

## Documentation closure

The containing follow-up commit records this already-observed publication,
updates the current checkpoint and completes M0's source-publication rows. It
does not change executable source or the workflow. Its exact commit, remote
readback and own hosted CI result are retained in the parent publication receipt;
this document cannot embed its own future commit identity. No tag or release is
created. Later commits do not erase this initial commit's verified CI result.

## Scope and remaining work

Only the nonprivileged help/version foundation exists. No worker/provider-backed
review or defensive product checkpoint is claimed; no privileged operations,
mounts, disk images or VM runs were performed. Native worker instruction loading
was verified separately during setup, not by this public push.

RH-001 remains the held next design task. Public Git protects committed source,
not private Kanban records, worker profiles, local verification logs or future
runtime data. Earlier setup receipts are historical snapshots, not current
license/publication approval gates.
