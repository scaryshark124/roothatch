package preflight

import (
	"fmt"
	"reflect"
	"testing"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// typeDetail is the exact interp_elf_invalid detail for a rejected e_type.
func typeDetail(n int, name string) string {
	return fmt.Sprintf("ELF type %d (%s) is not an executable or shared object", n, name) + interpNoteWant
}

// TestInterpHeaderType pins the e_type check of interpHeader: on an otherwise
// valid ELF64 little-endian x86-64 header only ET_EXEC and ET_DYN pass, and
// every other type is interp_elf_invalid naming the number and known name.
func TestInterpHeaderType(t *testing.T) {
	x86 := func(etype uint16) []byte { return pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, etype) }
	for name, b := range map[string][]byte{
		"ET_EXEC":           x86(pt.ETExec),
		"ET_DYN":            x86(pt.ETDyn),
		"ET_EXEC full ELF":  func() []byte { b := pt.LoaderELF(); b[16] = 2; return b }(),
		"ET_DYN trailing":   append(x86(pt.ETDyn), make([]byte, 4096)...),
		"ET_EXEC bytes 2,0": func() []byte { b := x86(0); b[16], b[17] = 2, 0; return b }(),
	} {
		if p := interpHeader(b); p != nil {
			t.Errorf("%s: %+v; want pass", name, p)
		}
	}
	for name, tc := range map[string]struct {
		b      []byte
		detail string
	}{
		"ET_NONE":          {x86(pt.ETNone), typeDetail(0, "ET_NONE")},
		"ET_REL":           {x86(pt.ETRel), typeDetail(1, "ET_REL")},
		"ET_CORE":          {x86(pt.ETCore), typeDetail(4, "ET_CORE")},
		"type 5":           {x86(5), typeDetail(5, "unknown")},
		"type 0xfe00":      {x86(0xfe00), typeDetail(0xfe00, "unknown")},
		"type 65535":       {x86(0xffff), typeDetail(65535, "unknown")},
		"ET_REL bytes 1,0": {func() []byte { b := x86(0); b[16], b[17] = 1, 0; return b }(), typeDetail(1, "ET_REL")},
		// Little-endian decoding: bytes 00 02 are 512, not ET_EXEC (2).
		"bytes 0,2 is 512": {func() []byte { b := x86(0); b[16], b[17] = 0, 2; return b }(), typeDetail(512, "unknown")},
		// And bytes 00 03 are 768, not ET_DYN (3).
		"bytes 0,3 is 768": {func() []byte { b := x86(0); b[16], b[17] = 0, 3; return b }(), typeDetail(768, "unknown")},
	} {
		p := interpHeader(tc.b)
		if p == nil || p.code != "interp_elf_invalid" || p.detail != tc.detail {
			t.Errorf("%s: %+v; want interp_elf_invalid %q", name, p, tc.detail)
		}
	}
}

// TestInterpHeaderTypeOrder pins that malformed/truncated headers keep their
// earlier interp_elf_invalid detail and unsupported architectures keep their
// interp_arch_unsupported finding even when e_type is also invalid.
func TestInterpHeaderTypeOrder(t *testing.T) {
	relLE := func(class byte, machine uint16) []byte {
		return pt.TypedHeader(class, pt.ELFDataLSB, machine, pt.ETRel)
	}
	for name, tc := range map[string]struct {
		b            []byte
		code, detail string
	}{
		"truncated ELF64 ET_REL": {relLE(pt.ELFClass64, pt.EMX8664)[:63], "interp_elf_invalid",
			"truncated ELF64 header (63 bytes; want 64)" + interpNoteWant},
		"truncated ELF64 at 17 ET_REL": {relLE(pt.ELFClass64, pt.EMX8664)[:17], "interp_elf_invalid",
			"truncated ELF64 header (17 bytes; want 64)" + interpNoteWant},
		"bad class ET_REL": {func() []byte { b := relLE(pt.ELFClass64, pt.EMX8664); b[4] = 3; return b }(), "interp_elf_invalid",
			"invalid ELF class 3" + interpNoteWant},
		"bad data ET_CORE": {func() []byte {
			b := pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, pt.ETCore)
			b[5] = 0
			return b
		}(), "interp_elf_invalid", "invalid ELF data encoding 0" + interpNoteWant},
		"bad ident version ET_NONE": {func() []byte {
			b := pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, pt.ETNone)
			b[6] = 0
			return b
		}(), "interp_elf_invalid", "unsupported ELF identification version 0" + interpNoteWant},
		"ELF64 LE AArch64 ET_REL": {relLE(pt.ELFClass64, pt.EMAArch64), "interp_arch_unsupported",
			"interpreter is ELF64 little-endian machine 183 (AArch64); want ELF64 little-endian x86-64 (62)" + interpNoteWant},
		"ELF32 LE x86-64 ET_CORE": {pt.TypedHeader(pt.ELFClass32, pt.ELFDataLSB, pt.EMX8664, pt.ETCore), "interp_arch_unsupported",
			"interpreter is ELF32 little-endian machine 62 (x86-64); want ELF64 little-endian x86-64 (62)" + interpNoteWant},
		"ELF64 BE x86-64 ET_REL": {pt.TypedHeader(pt.ELFClass64, pt.ELFDataMSB, pt.EMX8664, pt.ETRel), "interp_arch_unsupported",
			"interpreter is ELF64 big-endian machine 62 (x86-64); want ELF64 little-endian x86-64 (62)" + interpNoteWant},
		"ELF32 BE MIPS ET_REL": {pt.TypedHeader(pt.ELFClass32, pt.ELFDataMSB, pt.EMMIPS, pt.ETRel), "interp_arch_unsupported",
			"interpreter is ELF32 big-endian machine 8 (MIPS); want ELF64 little-endian x86-64 (62)" + interpNoteWant},
		"ELF32 BE MIPS type 65535": {pt.TypedHeader(pt.ELFClass32, pt.ELFDataMSB, pt.EMMIPS, 0xffff), "interp_arch_unsupported",
			"interpreter is ELF32 big-endian machine 8 (MIPS); want ELF64 little-endian x86-64 (62)" + interpNoteWant},
	} {
		p := interpHeader(tc.b)
		if p == nil || p.code != tc.code || p.detail != tc.detail {
			t.Errorf("%s: %+v; want %s %q", name, p, tc.code, tc.detail)
		}
	}
}

// TestTypedHeaderLayout checks the fixture generator itself: e_type and
// e_machine are encoded in the header's declared byte order and class layout,
// and each call returns fresh bytes.
func TestTypedHeaderLayout(t *testing.T) {
	be := pt.TypedHeader(pt.ELFClass32, pt.ELFDataMSB, pt.EMMIPS, pt.ETRel)
	if len(be) != 52 || be[4] != pt.ELFClass32 || be[5] != pt.ELFDataMSB ||
		!reflect.DeepEqual(be[16:20], []byte{0, 1, 0, 8}) || !reflect.DeepEqual(be[40:42], []byte{0, 52}) {
		t.Errorf("ELF32 big-endian header = % x", be)
	}
	le := pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, 0xffff)
	if len(le) != 64 || !reflect.DeepEqual(le[16:20], []byte{0xff, 0xff, 62, 0}) {
		t.Errorf("ELF64 little-endian header = % x", le)
	}
	le[16] = 9
	if again := pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, 0xffff); again[16] != 0xff {
		t.Error("TypedHeader returned shared bytes")
	}
	if b := pt.Header(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664); b[16] != 3 || b[17] != 0 {
		t.Errorf("Header e_type bytes = % x; want ET_DYN", b[16:18])
	}
}

// TestInterpTypeDetails runs Check on every interpreter type fixture and pins
// the exact findings (code, PT_INTERP path, detail).
func TestInterpTypeDetails(t *testing.T) {
	arch := "interpreter is ELF32 big-endian machine 8 (MIPS); want ELF64 little-endian x86-64 (62)" + interpNoteWant
	want := map[string][]Finding{
		"interp_type_none":              {{"interp_elf_invalid", pt.Loader, typeDetail(0, "ET_NONE")}},
		"interp_type_rel":               {{"interp_elf_invalid", pt.Loader, typeDetail(1, "ET_REL")}},
		"interp_type_core":              {{"interp_elf_invalid", pt.Loader, typeDetail(4, "ET_CORE")}},
		"interp_type_unknown_65535":     {{"interp_elf_invalid", pt.Loader, typeDetail(65535, "unknown")}},
		"interp_arch_elf32_be_bad_type": {{"interp_arch_unsupported", pt.Loader, arch}},
		"interp_type_exec":              nil,
	}
	seen := 0
	for _, fx := range pt.InterpTypeCatalog() {
		w, ok := want[fx.Name]
		if !ok {
			t.Errorf("fixture %s has no pinned expectation", fx.Name)
			continue
		}
		seen++
		t.Run(fx.Name, func(t *testing.T) {
			root, err := pt.BuildFixture(t.TempDir(), fx)
			if err != nil {
				t.Fatal(err)
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Findings, w) {
				t.Errorf("findings = %#v\nwant %#v", r.Findings, w)
			}
			checkFindingPairs(t, fx, r)
			if r.Interp != pt.Loader || r.Static {
				t.Errorf("Interp = %q Static = %v; want %q, false", r.Interp, r.Static, pt.Loader)
			}
		})
	}
	if seen != len(want) {
		t.Errorf("InterpTypeCatalog has %d of %d pinned fixtures", seen, len(want))
	}
}
