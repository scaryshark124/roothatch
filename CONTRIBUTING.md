# Contributing

Roothatch is pre-alpha and licensed under [Apache-2.0](LICENSE).
Repository: https://github.com/scaryshark124/roothatch.
Contributions intentionally submitted for inclusion follow Section 5
of the license unless explicitly stated otherwise. No separate CLA is required
by this project at present.

Use Go standard tooling and the [README](README.md) commands. Tie small changes
to checklist IDs, causal tests and the [delivery policy](docs/development/DELIVERY_POLICY.md).
Add dependencies only in accepted task scope. Current tests require no sudo.
Use disposable storage fixtures, never a contributor's system disk. Keep real
images, private logs and secrets out of Git.

Functional review and defensive checkpoints are distinct. Do not repair your own
independent findings. Public CI tests unprivileged code by default; privileged
integration needs a separately admitted disposable environment, never broad host
access or secrets in an untrusted pull-request job. Consult the
[current checkpoint](docs/development/CURRENT_STATE.md) and GitHub Actions for
actual hosted CI results; workflow configuration alone is not executed proof.
