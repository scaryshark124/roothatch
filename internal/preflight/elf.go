package preflight

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	elfPrefix = 64 << 10 // maximum bytes of /bin/sh ever read
	maxInterp = 4096     // PT_INTERP size cap, including the NUL

	emX8664    = 62
	phdrSize64 = 56
)

var machineNames = map[uint16]string{
	3: "i386", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "s390",
	40: "ARM", 183: "AArch64", 243: "RISC-V", 258: "LoongArch",
}

type elfProblem struct{ code, detail string }

func invalid(format string, args ...any) *elfProblem {
	return &elfProblem{"elf_invalid", fmt.Sprintf(format, args...)}
}

// parseELF validates the bounded prefix b of a file whose total size is size
// and returns its PT_INTERP string, if any. It never indexes or allocates from
// unchecked header values.
func parseELF(b []byte, size int64) (interp string, hasInterp bool, p *elfProblem) {
	if len(b) < 16 || string(b[:4]) != "\x7fELF" {
		return "", false, invalid("not an ELF file")
	}
	if b[4] != 2 {
		return "", false, &elfProblem{"arch_unsupported", fmt.Sprintf("ELF class %d is not ELF64; want ELF64 little-endian x86-64", b[4])}
	}
	if b[5] != 1 {
		return "", false, &elfProblem{"arch_unsupported", fmt.Sprintf("ELF data encoding %d is not little-endian; want ELF64 little-endian x86-64", b[5])}
	}
	if b[6] != 1 {
		return "", false, invalid("unsupported ELF identification version %d", b[6])
	}
	if len(b) < 64 {
		return "", false, invalid("truncated ELF64 header (%d bytes)", len(b))
	}
	le := binary.LittleEndian
	if m := le.Uint16(b[18:]); m != emX8664 {
		name := machineNames[m]
		if name == "" {
			name = "unknown"
		}
		return "", false, &elfProblem{"arch_unsupported", fmt.Sprintf("ELF machine %d (%s) is not x86-64 (62)", m, name)}
	}
	if t := le.Uint16(b[16:]); t != 2 && t != 3 {
		return "", false, invalid("ELF type %d is not an executable or shared object", t)
	}
	phoff := le.Uint64(b[32:])
	phentsize := uint64(le.Uint16(b[54:]))
	phnum := uint64(le.Uint16(b[56:]))
	switch {
	case phnum == 0xffff:
		return "", false, invalid("extended program header count is unsupported")
	case phnum == 0:
		return "", false, invalid("no program headers")
	case phentsize < phdrSize64:
		return "", false, invalid("program header entry size %d is smaller than %d", phentsize, phdrSize64)
	}
	fileSize := uint64(size)
	if fileSize < uint64(len(b)) {
		fileSize = uint64(len(b))
	}
	table := phentsize * phnum // both <= 0xffff: cannot overflow
	if phoff > fileSize || table > fileSize-phoff {
		return "", false, invalid("program header table extends past end of file")
	}
	if phoff > uint64(len(b)) || table > uint64(len(b))-phoff {
		return "", false, invalid("program header table lies beyond the inspected %d KiB prefix", elfPrefix>>10)
	}
	count := 0
	for i := uint64(0); i < phnum; i++ {
		ph := b[phoff+i*phentsize:]
		if le.Uint32(ph) != 3 { // PT_INTERP
			continue
		}
		if count++; count > 1 {
			return "", false, invalid("multiple PT_INTERP program headers")
		}
		off, n := le.Uint64(ph[8:]), le.Uint64(ph[32:])
		switch {
		case n < 2:
			return "", false, invalid("empty PT_INTERP")
		case n > maxInterp:
			return "", false, invalid("PT_INTERP longer than %d bytes", maxInterp)
		case off > fileSize || n > fileSize-off:
			return "", false, invalid("PT_INTERP extends past end of file")
		case off > uint64(len(b)) || n > uint64(len(b))-off:
			return "", false, invalid("PT_INTERP lies beyond the inspected %d KiB prefix", elfPrefix>>10)
		}
		s := b[off : off+n]
		if s[n-1] != 0 {
			return "", false, invalid("PT_INTERP is not NUL-terminated")
		}
		s = s[:n-1]
		if bytes.IndexByte(s, 0) >= 0 {
			return "", false, invalid("PT_INTERP contains an embedded NUL")
		}
		if s[0] != '/' {
			return "", false, invalid("PT_INTERP %q is not an absolute path", clean(string(s)))
		}
		interp, hasInterp = string(s), true
	}
	return interp, hasInterp, nil
}
