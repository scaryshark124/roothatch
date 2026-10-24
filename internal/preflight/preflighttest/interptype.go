package preflighttest

import "encoding/binary"

// EMMIPS is the MIPS e_machine number, used for the big-endian ELF32 fixture.
const EMMIPS = 8

// ELF file types (e_type) used by the interpreter type fixtures.
const (
	ETNone = 0
	ETRel  = 1
	ETExec = 2
	ETDyn  = 3
	ETCore = 4
)

// TypedHeader returns a fresh Header(class, data, machine) whose e_type is
// etype, encoded in that header's own byte order.
func TypedHeader(class, data byte, machine, etype uint16) []byte {
	b := Header(class, data, machine) // freshly allocated on every call
	var bo binary.ByteOrder = binary.LittleEndian
	if data == ELFDataMSB {
		bo = binary.BigEndian
	}
	bo.PutUint16(b[16:], etype)
	return b
}

// InterpTypeCatalog returns the interpreter e_type fixtures (also included in
// Catalog): a healthy /bin/sh whose PT_INTERP resolves inside the root to a
// regular file holding the given header, plus the valid boot layout. Only
// ET_EXEC and ET_DYN pass; an unsupported architecture is reported as such
// even when its type is also invalid.
func InterpTypeCatalog() []Fixture {
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	with := func(loader []byte) []Entry { return mergedUsr(shell(), File(ld, loader)) }
	bad := func(name, code string, loader []byte) Fixture {
		return Fixture{Name: name, Entries: with(loader), Want: []string{code},
			Findings: []FindingPair{{code, Loader}}}
	}
	x86 := func(etype uint16) []byte { return TypedHeader(ELFClass64, ELFDataLSB, EMX8664, etype) }
	return withBoot([]Fixture{
		bad("interp_type_none", "interp_elf_invalid", x86(ETNone)),
		bad("interp_type_rel", "interp_elf_invalid", x86(ETRel)),
		bad("interp_type_core", "interp_elf_invalid", x86(ETCore)),
		bad("interp_type_unknown_65535", "interp_elf_invalid", x86(0xffff)),
		bad("interp_arch_elf32_be_bad_type", "interp_arch_unsupported",
			TypedHeader(ELFClass32, ELFDataMSB, EMMIPS, ETRel)),
		{Name: "interp_type_exec", Entries: with(x86(ETExec))},
	})
}
