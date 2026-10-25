package preflighttest

import "os"

// InterpExecCatalog returns the interpreter permission-bit fixtures (also
// included in Catalog): a /bin/sh and a PT_INTERP target written with
// explicit modes, plus the valid boot layout. A valid x86-64 interpreter
// whose resolved regular file has no owner, group or other execute bit
// reports interp_not_executable at the PT_INTERP path, after any
// shell_not_executable; any one execute bit passes. Interpreters that fail
// their header check keep only that finding, and a static shell does no
// interpreter work. These are mode-bit checks only, not effective-access
// checks, and every mode keeps the file readable by its nonprivileged owner.
func InterpExecCatalog() []Fixture {
	const (
		sh   = "usr/bin/sh"
		ld   = "usr/lib64/ld-linux-x86-64.so.2"
		real = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
		rel  = "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	)
	dynamic := func(mode os.FileMode) Entry { return FileMode(sh, ELF(EMX8664, Loader), mode) }
	loader := func(mode os.FileMode) Entry { return FileMode(ld, LoaderELF(), mode) }
	notExec := FindingPair{"interp_not_executable", Loader}
	shellNotExec := FindingPair{"shell_not_executable", ShellPath}
	header := func(name, code string, data []byte) Fixture {
		return Fixture{Name: name, Entries: mergedUsr(dynamic(0o755), FileMode(ld, data, 0o644)),
			Want: []string{code}, Findings: []FindingPair{{code, Loader}}}
	}
	return withBoot([]Fixture{
		// Failures: the interpreter's own resolved mode has no execute bit.
		{Name: "interp_noexec_0644", Entries: mergedUsr(dynamic(0o755), loader(0o644)),
			Want: []string{"interp_not_executable"}, Findings: []FindingPair{notExec}},
		{Name: "interp_noexec_shell_noexec", Entries: mergedUsr(dynamic(0o644), loader(0o644)),
			Want:     []string{"shell_not_executable", "interp_not_executable"},
			Findings: []FindingPair{shellNotExec, notExec}},
		{Name: "interp_noexec_link_target", Entries: mergedUsr(dynamic(0o755), FileMode(real, LoaderELF(), 0o644), Link(ld, rel)),
			Want: []string{"interp_not_executable"}, Findings: []FindingPair{notExec}},
		// Passing controls: any one execute bit, a link to an executable
		// target, and an ET_EXEC loader.
		{Name: "interp_exec_owner_only", Entries: mergedUsr(dynamic(0o755), loader(0o744))},
		{Name: "interp_exec_group_only", Entries: mergedUsr(dynamic(0o755), loader(0o654))},
		{Name: "interp_exec_other_only", Entries: mergedUsr(dynamic(0o755), loader(0o645))},
		{Name: "interp_exec_link_target", Entries: mergedUsr(dynamic(0o755), FileMode(real, LoaderELF(), 0o755), Link(ld, rel))},
		{Name: "interp_exec_et_exec_0755", Entries: mergedUsr(dynamic(0o755),
			FileMode(ld, TypedHeader(ELFClass64, ELFDataLSB, EMX8664, ETExec), 0o755))},
		// Unchanged controls: earlier findings keep exactly their output.
		{Name: "interp_noexec_unused_static", Entries: mergedUsr(FileMode(sh, ELF(EMX8664, ""), 0o755), loader(0o644)),
			Static: true},
		header("interp_noexec_elf_text", "interp_elf_invalid", []byte("synthetic loader placeholder")),
		header("interp_noexec_arch_aarch64", "interp_arch_unsupported", Header(ELFClass64, ELFDataLSB, EMAArch64)),
		header("interp_noexec_type_rel", "interp_elf_invalid", TypedHeader(ELFClass64, ELFDataLSB, EMX8664, ETRel)),
		{Name: "interp_exec_shell_noexec", Entries: mergedUsr(dynamic(0o644), loader(0o755)),
			Want: []string{"shell_not_executable"}, Findings: []FindingPair{shellNotExec}},
	})
}
