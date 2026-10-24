package preflighttest

import "os"

// ShellPath is the in-root shell path every shell finding is reported at.
const ShellPath = "/bin/sh"

// ShellExecCatalog returns the shell permission-bit fixtures (also included
// in Catalog): a valid x86-64 /bin/sh written with an explicit mode, plus the
// valid boot layout. A shell whose resolved regular file has no owner, group
// or other execute bit reports shell_not_executable; any one execute bit
// passes. These are mode-bit checks only, not effective-access checks, and
// every mode keeps the file readable by its nonprivileged owner.
func ShellExecCatalog() []Fixture {
	const sh = "usr/bin/sh"
	dynamic := func(mode os.FileMode) Entry { return FileMode(sh, ELF(EMX8664, Loader), mode) }
	static := func(mode os.FileMode) Entry { return FileMode(sh, ELF(EMX8664, ""), mode) }
	notExec := FindingPair{"shell_not_executable", ShellPath}
	return withBoot([]Fixture{
		{Name: "shell_noexec_dynamic", Entries: mergedUsr(dynamic(0o644), loaderFile()),
			Want: []string{"shell_not_executable"}, Findings: []FindingPair{notExec}},
		{Name: "shell_noexec_static", Entries: mergedUsr(static(0o644)), Static: true,
			Want: []string{"shell_not_executable"}, Findings: []FindingPair{notExec}},
		{Name: "shell_noexec_missing_interp", Entries: mergedUsr(dynamic(0o644)),
			Want:     []string{"shell_not_executable", "interp_missing"},
			Findings: []FindingPair{notExec, {"interp_missing", Loader}}},
		{Name: "shell_exec_owner_only", Entries: mergedUsr(dynamic(0o744), loaderFile())},
		{Name: "shell_exec_group_only", Entries: mergedUsr(dynamic(0o654), loaderFile())},
		{Name: "shell_exec_other_only", Entries: mergedUsr(dynamic(0o645), loaderFile())},
	})
}
