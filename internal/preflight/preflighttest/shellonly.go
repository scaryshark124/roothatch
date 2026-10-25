package preflighttest

import "os"

// ShellOnlyPassLine is the exact final line "check --shell-only" prints when
// its limited shell checks pass.
const ShellOnlyPassLine = "PASS: limited shell checks passed (shell, ELF architecture, interpreter file type and ELF header, " +
	"shell and interpreter execute bits, symlink containment); /boot, /vmlinuz and /initrd.img were not checked as boot files; " +
	"this does not show the root is bootable or healthy"

// ShellOnlyFixture is a synthetic root with the exact ordered (code, path)
// findings expected from the shell-only check (Shell) and from the default
// full check (Default). These fixtures are separate from Catalog and
// EscapeCatalog and do not change them.
type ShellOnlyFixture struct {
	Name    string
	Entries []Entry
	Outside []Entry // outside-root sentinels, as in Fixture.Outside
	Static  bool    // shell-only pass expects the static-shell note
	Interp  string  // shell-only pass expects this PT_INTERP in the ok line
	Shell   []FindingPair
	Default []FindingPair
}

// Fixture converts f for BuildFixture.
func (f ShellOnlyFixture) Fixture() Fixture {
	return Fixture{Name: f.Name, Entries: f.Entries, Outside: f.Outside}
}

// ShellOnlyCatalog returns trees for "check --shell-only": healthy shells
// without /boot or with broken boot artifacts, today's shell-phase failures,
// combined shell and boot failures, and a PT_INTERP beneath /boot.
func ShellOnlyCatalog() []ShellOnlyFixture {
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	noBoot := FindingPair{"kernel_missing", BootPath}
	dynamic := func(mode os.FileMode) Entry { return FileMode("usr/bin/sh", ELF(EMX8664, Loader), mode) }
	bootSh := File("usr/bin/sh", ELF(EMX8664, "/boot/ld.so"))
	return []ShellOnlyFixture{
		{Name: "so_dynamic_no_boot", Entries: mergedUsr(shell(), loaderFile()), Interp: Loader,
			Shell: []FindingPair{}, Default: []FindingPair{noBoot}},
		{Name: "so_static_no_loader_no_boot", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, ""))), Static: true,
			Shell: []FindingPair{}, Default: []FindingPair{noBoot}},
		{Name: "so_dangling_vmlinuz", Entries: append(mergedUsr(shell(), loaderFile(), Link("vmlinuz", "boot/vmlinuz-absent")), BootLayout()...),
			Interp: Loader, Shell: []FindingPair{}, Default: []FindingPair{{"boot_link_broken", "/vmlinuz"}}},
		{Name: "so_escaping_kernel", Entries: mergedUsr(shell(), loaderFile(), Link("boot/vmlinuz-9.9-escape", "../../outside-kernel")),
			Outside: []Entry{sentinel("outside-kernel")}, Interp: Loader, Shell: []FindingPair{},
			Default: []FindingPair{{"symlink_escape", "/boot/vmlinuz-9.9-escape"}, noBoot}},
		{Name: "so_kernel_without_initrd", Entries: mergedUsr(shell(), loaderFile(), File("boot/vmlinuz-"+KernelVersion, []byte("k"))),
			Interp: Loader, Shell: []FindingPair{},
			Default: []FindingPair{{"initrd_missing", "/boot/initrd.img-" + KernelVersion}}},
		{Name: "so_missing_shell", Entries: mergedUsr(loaderFile()),
			Shell: []FindingPair{{"shell_missing", ShellPath}}, Default: []FindingPair{{"shell_missing", ShellPath}, noBoot}},
		{Name: "so_missing_interp", Entries: mergedUsr(shell()),
			Shell: []FindingPair{{"interp_missing", Loader}}, Default: []FindingPair{{"interp_missing", Loader}, noBoot}},
		{Name: "so_shell_noexec", Entries: mergedUsr(dynamic(0o644), loaderFile()),
			Shell:   []FindingPair{{"shell_not_executable", ShellPath}},
			Default: []FindingPair{{"shell_not_executable", ShellPath}, noBoot}},
		{Name: "so_interp_noexec", Entries: mergedUsr(dynamic(0o755), FileMode(ld, LoaderELF(), 0o644)),
			Shell:   []FindingPair{{"interp_not_executable", Loader}},
			Default: []FindingPair{{"interp_not_executable", Loader}, noBoot}},
		{Name: "so_missing_shell_dangling_vmlinuz", Entries: mergedUsr(loaderFile(), Link("vmlinuz", "boot/vmlinuz-absent")),
			Shell:   []FindingPair{{"shell_missing", ShellPath}},
			Default: []FindingPair{{"shell_missing", ShellPath}, noBoot, {"boot_link_broken", "/vmlinuz"}}},
		{Name: "so_boot_interp_missing", Entries: mergedUsr(bootSh),
			Shell:   []FindingPair{{"interp_missing", "/boot/ld.so"}},
			Default: []FindingPair{{"interp_missing", "/boot/ld.so"}, noBoot}},
		{Name: "so_boot_interp_valid", Entries: mergedUsr(bootSh, File("boot/ld.so", LoaderELF())), Interp: "/boot/ld.so",
			Shell: []FindingPair{}, Default: []FindingPair{noBoot}},
	}
}

// BootPath is the in-root /boot directory path boot findings are reported at.
const BootPath = "/boot"
