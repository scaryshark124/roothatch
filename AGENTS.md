# Roothatch development

This is an independent Go Linux build-and-rescue project. Read
`docs/development/CURRENT_STATE.md`, `MASTER_CHECKLIST.md`,
`docs/development/DELIVERY_POLICY.md` and the actual task before work.
Do not import Ironclad product requirements, private records or milestone gates.

## Roles

- Parent: requirements, task authoring, admission, direct verification and integration.
- `ironcladexec`: specified functional implementation and causal regression tests.
- `ironcladreview`: independent functional/specification review; findings-only.
- `ironcladsecurity`: separately scoped defensive checkpoints; no offensive work.

Use the six-section `docs/development/TASK_TEMPLATE.md`. Record
`TASK_SCOPE_CHECK: PASS` only for concrete requirements, tests, scope, effects,
exclusions and checkpoint disposition. One writer; reviewers do not repair their
own findings. Retain validation, permission, preservation and cleanup tests.

## Tracking and execution

Explicitly pin Hermes board/project `roothatch`. Parent setup stays unassigned
and non-dispatching. Assigned implementation uses same-card independent review
and correction. Card movement is not permission; worker PASS is not parent
acceptance. No automatic successor, goal loop or decomposition.
Preserve owner-selected models/accounts/permissions; no silent fallback.
Read relevant ordinary source as needed, not unrelated private projects or secrets.
Role names and instructions are not filesystem isolation or provider clearance.

## Development

Go standard tooling first: gofmt, go test, go vet, go build. New behavior requires
attributable failing-test proof. Dependencies need accepted task scope. No sudo,
mount/device/EFI/debootstrap/VM operations in bootstrap. Future runtime work needs
explicit disposable targets and scoped checkpoints before consequential live use.
Update affected checklist rows and current state with real results. Keep aggregate
outcomes open until complete. Preserve failed runs and separate functional from
defensive verdicts. Workers return unstaged changes; parent Git delivery requires
its actual owner grant.

## Public boundary

Keep local absolute paths, chat transcripts/IDs, secrets, disk images, installed
roots, private board exports, firmware state and raw diagnostic logs out of Git.
Use a separate local artifact root. Commit only sanitized portable summaries.
The intended open-source release does not authorize license selection or pushing.
