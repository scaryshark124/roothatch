# RH-M05 — `roothatch check --json` receipt

Date: 2026-10-24. **Functional acceptance of machine-readable output for the
existing checks.** No new diagnostic capability, not a security PASS,
bootability verdict or release.

## Delivered behavior

- `roothatch check --json <dir>` runs the existing checks once and writes one
  JSON document to stdout:
  `{"schema_version": 1, "result": "pass" | "findings", "findings": [{"code": ..., "path": ..., "detail": ...}]}`.
- Exactly those fields. `findings` is `[]` on a pass. Finding order and
  multiplicity match the text report; `path` and `detail` are the same
  sanitized strings the text output prints, then JSON-encoded.
- `"pass"` means only that the current limited checks passed.
- Exit status unchanged: 0 pass, 3 findings, 2 usage error or unusable
  directory, 1 output failure. Under `--json`, usage errors leave stdout empty
  and explain on stderr. Only `check --json <dir>` is accepted.
- Plain `check <dir>` output is unchanged.

## Executed verification

- Independent functional review: round 1 PASS, no material findings.
- Parent acceptance on a frozen copy of the reviewed candidate: `gofmt -l` empty,
  `go vet ./...`, `go test ./...`, `go test -race ./...` and `go build` passed;
  no skipped tests in the cli and binary suites.
- The previous release binary and the candidate binary ran on the same 60
  synthetic fixtures (the 54-fixture catalog plus 6 fixtures whose paths, link
  targets or ELF interpreter strings contain quotes, backslashes, control bytes
  and invalid UTF-8). Text-mode stdout, stderr and exit status were identical for
  all 60.
- Under `--json`, all 60 produced exactly one JSON value with exactly the
  documented fields, numeric `schema_version` 1, the expected `result` and exit
  status, valid UTF-8 strings, empty stderr and exactly the expected multiset of
  finding codes. Re-rendering the JSON findings reproduced the text finding block
  exactly. Lstat manifests were identical before and after every run.
- Eight wrong argument forms and unusable directories exited 2 with empty stdout;
  output to `/dev/full` exited 1 for both a pass and a findings report.
- Implementer failing-test-first evidence is author-reported and was not re-run.

## Limits

Schema version 1 only. Strings are the existing sanitized forms, not raw bytes.
The known gap that an escaping kernel candidate is not counted is unchanged.
Synthetic fixtures only; RH-M2-01 and RH-M5-01 remain open; the M1 design remains
held.
