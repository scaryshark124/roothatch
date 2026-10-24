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

## Bounded functional milestones — BOUNDED-FUNCTIONAL-MILESTONES-V1

Owner-accepted (RH-D005). Load the `bounded-functional-milestones` skill before any dispatch, wake handling or continuation, and after compaction. Work only inside an owner-approved milestone with one observable functional outcome and an acceptance test; documentation alone is not completion unless approved as the deliverable. One shared allowance per milestone: 2 h wall clock, 4 provider-backed worker runs, 150 completed model calls, 40M cumulative prompt tokens, 1 concurrent worker, across coordinator, workers, reviewers and auxiliary work. New cards, sessions, retries, compaction, review handoffs and wakes never reset it. Create cards only through the skill's `create-card` helper: max runtime <= min(2 h, remaining wall time), max retries 1, notify-only subscription. Run its `status` before every dispatch and before acting on any notification; STOP means a short checkpoint and wait. Stop also on the same blocker after two correction/review rounds, or when a required review/checkpoint cannot fit; split or renegotiate, never skip it. Never create successor cards, renew the allowance or start the next milestone without explicit owner approval. Workers: finish or block with a concrete reason within the card's limits; no redelegation, goal loops or scope expansion.

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
