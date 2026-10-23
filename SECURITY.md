# Security and data preservation

Pre-alpha: no supported release and no privileged product functionality yet.
Do not run the scaffold as root or use it to repair a real installation.

Planned sensitive boundaries include path resolution, mounts, devices, images,
bootloaders and virtual firmware. Preserve target identity, reject concurrent
writers, prevent unintended host writes and clean only owned resources.
Chroot alone is not a security sandbox.

Scoped defensive checkpoints precede privileged implementation, consequential
real-target use and public binaries. Functional tests retain validation,
permissions, safe diagnostics and preservation. One checkpoint is not whole-host
assurance.

Select a public vulnerability-reporting channel before release. Until then use
an established private channel with the owner; do not publish secrets, disk
images or sensitive exploit details. No invented inbox or response SLA is claimed.
