package preflight

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// TestInterpExecDetails runs Check on every interpreter permission-bit
// fixture and pins the exact findings (code, path, detail), Static and
// Interp. Header-rejected interpreters keep exactly their existing detail.
func TestInterpExecDetails(t *testing.T) {
	interpNE := Finding{"interp_not_executable", pt.Loader, noExecDetail("0644")}
	shellNE := Finding{"shell_not_executable", ShellPath, noExecDetail("0644")}
	type want struct {
		findings []Finding
		static   bool
		interp   string
	}
	pinned := map[string]want{
		"interp_noexec_0644":          {[]Finding{interpNE}, false, pt.Loader},
		"interp_noexec_shell_noexec":  {[]Finding{shellNE, interpNE}, false, pt.Loader},
		"interp_noexec_link_target":   {[]Finding{interpNE}, false, pt.Loader},
		"interp_exec_owner_only":      {nil, false, pt.Loader},
		"interp_exec_group_only":      {nil, false, pt.Loader},
		"interp_exec_other_only":      {nil, false, pt.Loader},
		"interp_exec_link_target":     {nil, false, pt.Loader},
		"interp_exec_et_exec_0755":    {nil, false, pt.Loader},
		"interp_noexec_unused_static": {nil, true, ""},
		"interp_noexec_elf_text": {[]Finding{{"interp_elf_invalid", pt.Loader,
			"not an ELF file" + interpNoteWant}}, false, pt.Loader},
		"interp_noexec_arch_aarch64": {[]Finding{{"interp_arch_unsupported", pt.Loader,
			"interpreter is ELF64 little-endian machine 183 (AArch64); want ELF64 little-endian x86-64 (62)" + interpNoteWant}}, false, pt.Loader},
		"interp_noexec_type_rel":   {[]Finding{{"interp_elf_invalid", pt.Loader, typeDetail(1, "ET_REL")}}, false, pt.Loader},
		"interp_exec_shell_noexec": {[]Finding{shellNE}, false, pt.Loader},
	}
	inCatalog := map[string]bool{}
	for _, fx := range pt.Catalog() {
		inCatalog[fx.Name] = true
	}
	fxs := pt.InterpExecCatalog()
	if len(fxs) != len(pinned) {
		t.Fatalf("InterpExecCatalog has %d fixtures; want %d", len(fxs), len(pinned))
	}
	for _, fx := range fxs {
		w, ok := pinned[fx.Name]
		if !ok || !inCatalog[fx.Name] {
			t.Fatalf("fixture %s: pinned %v, in Catalog() %v", fx.Name, ok, inCatalog[fx.Name])
		}
		t.Run(fx.Name, func(t *testing.T) {
			root, err := pt.BuildFixture(t.TempDir(), fx)
			if err != nil {
				t.Fatal(err)
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Findings, w.findings) {
				t.Errorf("findings = %#v\nwant %#v", r.Findings, w.findings)
			}
			checkFindingPairs(t, fx, r)
			if r.Static != w.static || r.Interp != w.interp {
				t.Errorf("Static = %v Interp = %q; want %v %q", r.Static, r.Interp, w.static, w.interp)
			}
		})
	}
}

// TestInterpExecFixtureModes proves the fixtures exercise what they claim:
// the link fixtures' PT_INTERP path is a symlink (lstat mode 0777 on Linux)
// whose regular target carries the tested mode, and every other loader is a
// regular file with its explicit mode.
func TestInterpExecFixtureModes(t *testing.T) {
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	const real = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	for name, w := range map[string]struct {
		link bool
		mode os.FileMode
	}{
		"interp_noexec_0644":        {false, 0o644},
		"interp_noexec_link_target": {true, 0o644},
		"interp_exec_link_target":   {true, 0o755},
		"interp_exec_group_only":    {false, 0o654},
		"interp_exec_other_only":    {false, 0o645},
	} {
		var fx pt.Fixture
		for _, f := range pt.InterpExecCatalog() {
			if f.Name == name {
				fx = f
			}
		}
		root, err := pt.BuildFixture(t.TempDir(), fx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		li, err := os.Lstat(filepath.Join(root, ld))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		target := ld
		if w.link {
			if li.Mode()&os.ModeSymlink == 0 || li.Mode().Perm()&0o111 == 0 {
				t.Errorf("%s: PT_INTERP path mode %v; want a symlink whose own mode has execute bits", name, li.Mode())
			}
			target = real
		}
		ti, err := os.Lstat(filepath.Join(root, target))
		if err != nil || !ti.Mode().IsRegular() || ti.Mode().Perm() != w.mode {
			t.Errorf("%s: target %s mode = %v (%v); want regular %v", name, target, ti, err, w.mode)
		}
	}
}

// TestInterpExecPrecedence pins where interp_not_executable sits: it is
// decided from the interpreter's own resolved mode (never the shell's or a
// link's), only after the interpreter header passes, after any
// shell_not_executable, and never for read failures, header failures,
// resolution failures or static shells.
func TestInterpExecPrecedence(t *testing.T) {
	const sh = "usr/bin/sh"
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	dyn := pt.ELF(pt.EMX8664, pt.Loader)
	entry := func(e pt.Entry) *pt.Entry { return &e }
	loader := func(mode os.FileMode) *pt.Entry { return entry(pt.FileMode(ld, pt.LoaderELF(), mode)) }
	hdr := func(b []byte) *pt.Entry { return entry(pt.FileMode(ld, b, 0o644)) }
	x86 := func(etype uint16) []byte { return pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, etype) }
	ine := func(mode string) Finding { return Finding{"interp_not_executable", pt.Loader, noExecDetail(mode)} }
	sne := func(mode string) Finding { return Finding{"shell_not_executable", ShellPath, noExecDetail(mode)} }
	for _, tc := range []struct {
		name    string
		entries []pt.Entry
		want    []Finding // exact findings when set
		codes   []string  // exact codes when want is nil
	}{
		// ist, not st: each finding follows its own file's mode.
		{"exec shell noexec interp", shellTree(loader(0o644), pt.FileMode(sh, dyn, 0o755)), []Finding{ine("0644")}, nil},
		{"noexec shell exec interp", shellTree(loader(0o755), pt.FileMode(sh, dyn, 0o644)), []Finding{sne("0644")}, nil},
		{"distinct modes named", shellTree(loader(0o604), pt.FileMode(sh, dyn, 0o600)), []Finding{sne("0600"), ine("0604")}, nil},
		{"interp mode 0400", shellTree(loader(0o400), pt.FileMode(sh, dyn, 0o711)), []Finding{ine("0400")}, nil},
		{"interp mode 0444", shellTree(loader(0o444), pt.FileMode(sh, dyn, 0o755)), []Finding{ine("0444")}, nil},
		{"interp owner exec 0700", shellTree(loader(0o700), pt.FileMode(sh, dyn, 0o644)), []Finding{sne("0644")}, nil},
		{"interp group exec 0610", shellTree(loader(0o610), pt.FileMode(sh, dyn, 0o755)), nil, []string{}},
		{"interp other exec 0601", shellTree(loader(0o601), pt.FileMode(sh, dyn, 0o755)), nil, []string{}},
		{"interp owner r-x 0500", shellTree(loader(0o500), pt.FileMode(sh, dyn, 0o755)), nil, []string{}},
		// Link mode is never consulted; the resolved target's is.
		{"link to noexec interp", shellTree(entry(pt.Link(ld, "ld.real")), pt.FileMode(sh, dyn, 0o755),
			pt.FileMode("usr/lib64/ld.real", pt.LoaderELF(), 0o644)), []Finding{ine("0644")}, nil},
		{"link to exec interp", shellTree(entry(pt.Link(ld, "ld.real")), pt.FileMode(sh, dyn, 0o755),
			pt.FileMode("usr/lib64/ld.real", pt.LoaderELF(), 0o755)), nil, []string{}},
		// Header failures keep only their own finding.
		{"noexec empty stays interp_elf_invalid", shellTree(hdr(nil), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_elf_invalid"}},
		{"noexec truncated stays interp_elf_invalid", shellTree(hdr(x86(pt.ETDyn)[:63]), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_elf_invalid"}},
		{"noexec ET_NONE stays interp_elf_invalid", shellTree(hdr(x86(pt.ETNone)), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_elf_invalid"}},
		{"noexec ET_CORE stays interp_elf_invalid", shellTree(hdr(x86(pt.ETCore)), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_elf_invalid"}},
		{"noexec i386 stays interp_arch_unsupported", shellTree(hdr(pt.Header(pt.ELFClass32, pt.ELFDataLSB, pt.EMI386)), pt.FileMode(sh, dyn, 0o755)),
			nil, []string{"interp_arch_unsupported"}},
		{"noexec big-endian stays interp_arch_unsupported", shellTree(hdr(pt.Header(pt.ELFClass64, pt.ELFDataMSB, pt.EMX8664)), pt.FileMode(sh, dyn, 0o755)),
			nil, []string{"interp_arch_unsupported"}},
		{"both noexec header failure", shellTree(hdr([]byte("not elf")), pt.FileMode(sh, dyn, 0o644)), nil,
			[]string{"shell_not_executable", "interp_elf_invalid"}},
		// Resolution failures are unchanged.
		{"missing interp", shellTree(entry(pt.Dir("usr/lib64")), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_missing"}},
		{"fifo interp", shellTree(entry(pt.FIFO(ld)), pt.FileMode(sh, dyn, 0o755)), nil, []string{"interp_not_regular"}},
		{"looping interp", shellTree(entry(pt.Link(ld, "/lib64/ld-linux-x86-64.so.2")), pt.FileMode(sh, dyn, 0o755)), nil, []string{"symlink_loop"}},
		{"escaping interp", shellTree(entry(pt.Link(ld, "../../../../outside/ld")), pt.FileMode(sh, dyn, 0o755)), nil, []string{"symlink_escape"}},
		// Static shells never look at a loader.
		{"static shell noexec loader", shellTree(loader(0o644), pt.FileMode(sh, pt.ELF(pt.EMX8664, ""), 0o755)), nil, []string{}},
		{"static noexec shell noexec loader", shellTree(loader(0o644), pt.FileMode(sh, pt.ELF(pt.EMX8664, ""), 0o644)), []Finding{sne("0644")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runCheck(t, build(t, tc.entries...))
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != nil {
				if !reflect.DeepEqual(r.Findings, tc.want) {
					t.Errorf("findings = %#v\nwant %#v", r.Findings, tc.want)
				}
			} else if got := codes(r); !reflect.DeepEqual(got, tc.codes) {
				t.Errorf("codes = %v; want %v (%+v)", got, tc.codes, r.Findings)
			}
			for _, f := range r.Findings {
				if f.Code == "interp_not_executable" && f.Path != pt.Loader {
					t.Errorf("interp_not_executable at %q; want the PT_INTERP path %q", f.Path, pt.Loader)
				}
			}
		})
	}
}

// TestInterpExecWithBootFindings shows the interpreter and /boot checks stay
// independent: a non-executable loader and a missing /boot both report.
func TestInterpExecWithBootFindings(t *testing.T) {
	root := build(t, pt.Link("bin", "usr/bin"), pt.Link("lib64", "usr/lib64"),
		pt.FileMode("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader), 0o755),
		pt.FileMode("usr/lib64/ld-linux-x86-64.so.2", pt.LoaderELF(), 0o644))
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []pt.FindingPair{{Code: "interp_not_executable", Path: pt.Loader}, {Code: "kernel_missing", Path: BootDir}}
	if got := pairs(r); !reflect.DeepEqual(got, want) {
		t.Errorf("pairs = %v; want %v", got, want)
	}
}

// TestInterpUnreadableStaysReadError: a loader at mode 000 cannot be read by
// a nonprivileged runner, so it keeps exactly its read_error finding and gets
// no permission finding.
func TestInterpUnreadableStaysReadError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not deny root")
	}
	const ld = "usr/lib64/ld-linux-x86-64.so.2"
	root := build(t, shellTree(entry0(pt.FileMode(ld, pt.LoaderELF(), 0)), pt.FileMode("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader), 0o755))...)
	p := filepath.Join(root, ld)
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	if fi, err := os.Lstat(p); err != nil || fi.Mode().Perm() != 0 {
		t.Fatalf("fixture loader mode = %v (%v); want 000", fi, err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Code != "read_error" || r.Findings[0].Path != pt.Loader ||
		!strings.HasPrefix(r.Findings[0].Detail, "cannot read: ") {
		t.Errorf("findings = %#v; want exactly one read_error at %s", r.Findings, pt.Loader)
	}
}

func entry0(e pt.Entry) *pt.Entry { return &e }
