# RH-M08 — ELF interpreter header receipt

Date: 2026-10-24. **Functional acceptance of a header-level interpreter check.**
Not a security PASS, loader-functionality or bootability verdict, or release.

## Delivered behavior

- After `/bin/sh`'s PT_INTERP resolves inside the root to a regular file, `check`
  reads it through the existing descriptor-pinned, bounded reader (up to 64 KiB,
  as for `/bin/sh`) using the descriptor the confined resolver returned. The
  descriptor is closed on success and on failure.
- A narrow header helper examines only ELF identification, the class-specific
  header length (52 bytes ELF32, 64 bytes ELF64) and `e_machine` in the declared
  byte order. It never follows header-declared offsets or program headers.
  - not ELF, invalid class/data/identification version, or truncated header ->
    `interp_elf_invalid` at the PT_INTERP path;
  - a complete header that is not ELF64 little-endian x86-64 ->
    `interp_arch_unsupported` at the PT_INTERP path;
  - a read failure -> `read_error` at the PT_INTERP path (previously an
    unreadable interpreter passed silently).
- Details state that this is a header-level check, not a verdict that the loader
  works.
- Unchanged: missing/escaping/looping/non-regular interpreter findings, static
  shells, `/bin/sh` diagnosis, `/boot`, kernel/initrd and shortcut checks, the
  resolver, the `ok:`/`PASS:` lines, exit codes and JSON schema 1.
- Supersedes the RH-M01 limit that the interpreter was checked only for presence
  and file type; earlier receipts remain as written.

## Executed verification

- Independent functional review: round 1 PASS, no material findings.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed;
  the real-binary unreadable-interpreter test ran and no tests were skipped.
- Source boundary: only `checkShell` changed among the checker functions;
  `parseELF`, the resolver, `regularIn`, `readPinned`, `locate`, `/boot` and
  shortcut checks were byte-identical, and `elf.go` changed only by appending the
  helper.
- Fixture catalog: all 67 earlier fixtures kept their names, expectations, kernel
  and shortcut lists and outside sentinels; the only data changes were 46
  placeholder loader files replaced by generated valid ELF64 little-endian
  x86-64 headers. The 13 new fixtures were checked independently by decoding
  their loader bytes against the intended header class.
- The previous release binary and the candidate ran on the same 80 updated
  fixture trees in text and `--json` modes. All 67 earlier fixtures and the three
  new passing controls (relative and absolute in-tree loader links, and a 1 MiB
  loader with a valid header) produced byte-identical stdout, stderr and exit
  status. The ten new failing fixtures passed under the previous binary and,
  under the candidate, produced exactly one finding at the interpreter path:
  `interp_elf_invalid` for text, empty, truncated ELF64/ELF32 and invalid
  class/data/version headers; `interp_arch_unsupported` for AArch64, ELF32 i386
  and big-endian x86-64 headers. JSON findings reproduced the text block, stderr
  was empty, and fail-closed manifests of the whole sandbox were identical before
  and after every run.
- Unreadable interpreter, run unprivileged: with the loader at mode 000 and read
  denial confirmed, the previous binary passed and the candidate reported exactly
  `read_error` at the interpreter path (exit 3); sandbox metadata was unchanged
  around every run, and after restoring the mode the loader content hash and full
  manifest matched the original.
- Implementer failing-test-first evidence is author-reported; the reviewer
  separately confirmed the new tests fail with the production change reverted.

## Limits

Header-level only: no `e_type`, ABI, program-header, dependency or execution
checks, and no proof that the loader runs. Synthetic fixtures only. RH-M2-01 and
RH-M5-01 remain open; the M1 design remains held.
