# RH-M09 — ELF interpreter file type receipt

Date: 2026-10-24. **Functional acceptance of a header-level interpreter type
check.** Not a security PASS, loader-functionality or bootability verdict, or
release.

## Delivered behavior

- After the interpreter header is confirmed to be a complete ELF64
  little-endian x86-64 header, `check` reads `e_type` (offset 16, declared byte
  order) from the bytes already read. `ET_EXEC` (2) and `ET_DYN` (3) pass; any
  other type reports `interp_elf_invalid` at the PT_INTERP path, naming the type
  (`ET_NONE`, `ET_REL`, `ET_CORE`, otherwise unknown), with the existing
  header-level note.
- Malformed, truncated and non-x86-64 interpreter headers keep their earlier
  findings; a foreign header with a bad type reports only its architecture
  finding.
- No new reads, opens or path handling. Unchanged: `/bin/sh` diagnosis (which
  already required `ET_EXEC`/`ET_DYN`), the reader, resolver, `/boot`, kernel,
  initrd and shortcut checks, `ok:`/`PASS:` lines, exit codes and JSON schema 1.
- Supersedes the RH-M08 receipt's limit that the interpreter's `e_type` was not
  checked; earlier receipts remain as written.

## Executed verification

- Independent functional review: round 1 PASS; the reviewer reproduced the new
  tests failing with the production change reverted.
- One existing unit-test expectation changed, as authorized by the coordinator
  within the approved outcome: `TestInterpHeaderBoundary` now expects an
  `ET_REL` interpreter header to be rejected. Its other accepted cases
  (`e_version` 0, OS ABI, hostile table offsets/counts, trailing bytes) are
  unchanged. No fixture expectation changed.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed; the
  new real-binary type test ran and no tests were skipped. Only `interpHeader`
  changed among production functions.
- Fixture catalog: all 80 earlier fixtures are identical (definitions,
  bytes, expectations and sentinels); the 6 new fixtures' loader bytes were
  decoded independently (types 0, 1, 4, 65535 and 2 on ELF64 little-endian
  x86-64, and an ELF32 big-endian MIPS header with type 1).
- The previous release binary and the candidate ran on the same 86
  fixture trees in text and `--json` modes. 82 produced
  byte-identical stdout, stderr and exit status, including the `ET_EXEC` control
  and the foreign bad-type control. Only the four type-rejection fixtures
  changed: each passed before and now reports exactly `interp_elf_invalid` at the
  interpreter path naming its type (exit 3). JSON findings reproduced the text
  block, stderr was empty, and fail-closed sandbox manifests were identical
  before and after every run.
- Unreadable interpreter, run unprivileged with read denial confirmed: both
  binaries reported the same `read_error` (exit 3); metadata was unchanged
  around every run and content was restored.

## Limits

Header-level only: no ABI, `e_version`, program-header, permission, dependency or
execution checks, and no proof that the loader runs. Synthetic fixtures only.
RH-M2-01 and RH-M5-01 remain open; the M1 design remains held.
