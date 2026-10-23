# Durable board

Hermes project and board: **roothatch**, separate from Ironclad.
Use `hermes kanban --board roothatch ...` explicitly. The project registry links
to this board and its default workdir is the source directory. Tasks still bind
their workspace explicitly; do not assume automatic project/worktree inheritance
or rely on the global active selection.

## Roles and transitions

Parent governs/verifies/integrates. ironcladexec writes specified functionality;
ironcladreview independently reviews; ironcladsecurity owns a named defensive
checkpoint. Roothatch-specific profile instructions and native project-context
loading are verified, including nested source directories and cache invalidation.
This is instruction-loading proof, not a live worker/provider/tool-admission run;
qualify the actual task and runtime prerequisites before the first dispatch.

Assigned work uses same-card implementation -> review -> correction or reviewed
completion. Parent acceptance follows direct checks. Separate security/release
phases use distinct bounded cards. Do not duplicate every checklist row into an
automatically runnable graph.

## Safe assembly

Create cards unassigned while binding authority and scope. Verify sticky holds
and zero worker runs for parked tasks; a status label alone is not sufficient on
all runtime versions. Read back board/project/workspace, role, current run and
attachments before dispatch/closure. No default assignee, auto-decomposition,
goal loop or worker launch is established by bootstrap.

Tasks include the [six-section contract](TASK_TEMPLATE.md), exact source/candidate,
proof, granted/withheld effects, current selected route and task-shaped bounds.
Use unique generation filenames for attachments and verify stored hashes.
Card status, assignment and reviewer PASS never create owner authority.

## Notifications and public boundary

Worker handoffs should use the owner's project conversation with `notify+wake`
when parent follow-up is needed. Verify exact subscriptions; configuration is not
proof of delivery. Parent bootstrap may be intentionally silent. Keep local chat
identifiers, provider settings and raw board exports outside public Git.

Preserve existing profile models/accounts/tool permissions and holds. Read the
current checkpoint before acting; a documented desired role is not a qualified
worker launch. Public GitHub Projects/Issues can be added later if requested;
the native board supplies durable orchestration without a public service setup.
