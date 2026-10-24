# RH-M07 — escaping initrd links receipt

Date: 2026-10-24. **Functional acceptance of a diagnostic for an existing
containment refusal.** No new filesystem access or confinement behavior; not a
security PASS, bootability verdict or release.

## Delivered behavior

- When the matching `/boot/initrd.img-<version>` for a valid kernel resolves
  outside the root, `check` reports `symlink_escape` at that in-root initrd path
  with the resolver's existing escape detail, immediately followed by the
  existing `initrd_missing` for that version with unchanged detail text.
- The initrd is never followed; the kernel is still counted, so no
  `kernel_missing` results from it.
- Unchanged: the resolver, missing/dangling/looping/non-regular initrds, kernel
  candidates (including RH-M06 kernel escapes), shortcut links, `/boot` itself,
  shell/interpreter checks, exit codes, text format and JSON schema 1.
- This supersedes the RH-M06 receipt's limit that escaping initrd links were
  reported only as `initrd_missing`; that receipt remains as written.

## Executed verification

- Independent functional review: round 1 PASS, no material findings.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed;
  the new real-binary initrd test ran and no tests were skipped.
- The previous release binary and the candidate binary ran on the same 67
  synthetic fixtures in text and `--json` modes. 64 produced byte-identical
  stdout, stderr and exit status, including the in-tree initrd link controls and
  the RH-M06 kernel-escape fixtures. Only the three escaping-initrd fixtures
  changed, adding exactly one, one and two `symlink_escape` findings.
- For those three, each added finding named the initrd path and immediately
  preceded that version's `initrd_missing`; removing only the added findings
  reproduced the previous findings exactly (code, path, detail and order); both
  versions exited 3 with `result` `findings`; and the FAIL count matched the
  actual number of findings (1 to 2, 1 to 2, 2 to 4).
- For every fixture, JSON findings reproduced the text finding block, stderr was
  empty, and fail-closed manifests of the whole sandbox (root plus outside-root
  sentinel files the escaping links point at) were identical before and after
  every run. Unchanged sentinels show they were not modified, not that they were
  not read.
- Implementer failing-test-first evidence is author-reported and was not re-run.

## Limits

Synthetic fixtures only. The detail text of the new finding repeats the escape
description already present in `initrd_missing`. RH-M2-01 and RH-M5-01 remain
open; the M1 design remains held.
