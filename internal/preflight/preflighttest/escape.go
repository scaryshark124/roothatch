package preflighttest

// Nasty is a string containing a double quote, backslashes, control bytes
// (newline, tab, 0x01) and an invalid UTF-8 byte (0xff). It contains no "/"
// or NUL, so it can be used as a single path component or link target.
const Nasty = "q\"b\\n\nt\tc\x01x\xffz"

// EscapeCatalog returns fixtures whose symlink targets, ELF PT_INTERP strings
// or /boot entry names contain Nasty, so the reported (sanitized) paths and
// details are derived from hostile bytes. They supplement Catalog and do not
// change any of its entries.
func EscapeCatalog() []Fixture {
	return withBoot([]Fixture{
		{Name: "escape_bytes_interp_missing", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, "/lib64/"+Nasty))),
			Want: []string{"interp_missing"}},
		{Name: "escape_bytes_interp_relative", Entries: mergedUsr(File("usr/bin/sh", ELF(EMX8664, Nasty)), loaderFile()),
			Want: []string{"elf_invalid"}},
		{Name: "escape_bytes_shell_dangling", Entries: mergedUsr(Link("usr/bin/sh", Nasty), loaderFile()),
			Want: []string{"shell_missing"}},
		{Name: "escape_bytes_shell_escape", Entries: mergedUsr(Link("usr/bin/sh", "../../../../"+Nasty)),
			Want: []string{"symlink_escape"}},
		{Name: "escape_bytes_interp_link_dangling", Entries: mergedUsr(shell(), Link("usr/lib64/ld-linux-x86-64.so.2", Nasty)),
			Want: []string{"interp_missing"}},
		{Name: "escape_bytes_kernel_without_initrd", Entries: mergedUsr(shell(), loaderFile(),
			File("boot/vmlinuz-"+Nasty, []byte("k"))), Want: []string{"initrd_missing"}},
	})
}
