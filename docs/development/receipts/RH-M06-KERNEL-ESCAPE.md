# RH-M06 — escaping kernel candidates receipt

Date: 2026-10-24. **Functional acceptance of a diagnostic for an existing
containment refusal.** No new filesystem access or confinement behavior; not a
security PASS, bootability verdict or release.

## Delivered behavior

- A `/boot/vmlinuz-<version>` candidate whose resolution leads outside the root
  is reported as `symlink_escape` at that in-root candidate path, with the
  resolver's existing escape detail. Previously it was silently ignored.
- The candidate is still never followed, never counted as a kernel and gets no
  initrd check. A valid kernel/initrd pair elsewhere no longer hides it.
- With no valid kernel, the existing `kernel_missing` finding is reported as
  before, with unchanged detail text.
- Unchanged: the resolver, dangling/looping/non-regular/empty-version kernel
  candidates, escaping initrds (still `initrd_missing`), shortcut links, `/boot`
  itself, shell/interpreter checks, exit codes, text format and JSON schema 1.
- The finding detail quotes the link target; for an absolute target that is a
  host path from the inspected tree's own data.

## Executed verification

- Independent functional review: round 1 PASS, no material findings.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed;
  no skipped tests in the cli, binary and preflight suites.
- The previous release binary and the candidate binary ran on the same 63
  synthetic fixtures in text and `--json` modes. 60 produced byte-identical
  stdout, stderr and exit status. Only the three intended fixtures changed:
  - the existing escaping-kernel fixture gained one `symlink_escape` at the
    kernel path and kept an identical `kernel_missing` line;
  - a valid pair plus one escaping kernel changed from pass to exactly one
    `symlink_escape` (exit 3, no `kernel_missing`);
  - a valid pair plus relative and absolute escaping kernels changed from pass
    to exactly two `symlink_escape` findings at distinct kernel paths.
- For every fixture, finding codes and paths matched expectations exactly and in
  order, JSON findings reproduced the text finding block, stderr was empty, and
  fail-closed manifests of the whole sandbox (root plus outside-root sentinel
  files the escaping links point at) were identical before and after every run.
  Unchanged sentinels show they were not modified, not that they were not read.
- Implementer failing-test-first evidence is author-reported and was not re-run.

## Limits

Synthetic fixtures only. Escaping initrd links are still reported as
`initrd_missing`, not `symlink_escape`. RH-M2-01 and RH-M5-01 remain open; the M1
design remains held.
