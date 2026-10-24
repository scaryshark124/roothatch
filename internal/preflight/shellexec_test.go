package preflight

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// noExecDetail is the exact shell_not_executable detail for a resolved shell
// whose permission mode is mode.
func noExecDetail(mode string) string {
	return "resolves to a regular file with mode " + mode +
		"; no owner, group or other execute bit is set (mode bits only; not a check of whether any user can run it)"
}

// TestShellExecDetails runs Check on every shell permission-bit fixture and
// pins the exact findings (code, path, detail), Static and Interp.
func TestShellExecDetails(t *testing.T) {
	missing := "/usr/lib64/ld-linux-x86-64.so.2 does not exist inside the root"
	type want struct {
		findings []Finding
		static   bool
		interp   string
	}
	pinned := map[string]want{
		"shell_noexec_dynamic": {[]Finding{{"shell_not_executable", ShellPath, noExecDetail("0644")}}, false, pt.Loader},
		"shell_noexec_static":  {[]Finding{{"shell_not_executable", ShellPath, noExecDetail("0644")}}, true, ""},
		"shell_noexec_missing_interp": {[]Finding{
			{"shell_not_executable", ShellPath, noExecDetail("0644")},
			{"interp_missing", pt.Loader, missing},
		}, false, pt.Loader},
		"shell_exec_owner_only": {nil, false, pt.Loader},
		"shell_exec_group_only": {nil, false, pt.Loader},
		"shell_exec_other_only": {nil, false, pt.Loader},
	}
	inCatalog := map[string]bool{}
	for _, fx := range pt.Catalog() {
		inCatalog[fx.Name] = true
	}
	fxs := pt.ShellExecCatalog()
	if len(fxs) != len(pinned) {
		t.Fatalf("ShellExecCatalog has %d fixtures; want %d", len(fxs), len(pinned))
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

// shellTree is a merged-/usr tree with the given /usr/bin entries, a healthy
// interpreter unless loader is non-nil, and the valid boot layout.
func shellTree(loader *pt.Entry, bin ...pt.Entry) []pt.Entry {
	ld := pt.File("usr/lib64/ld-linux-x86-64.so.2", pt.LoaderELF())
	if loader != nil {
		ld = *loader
	}
	e := append([]pt.Entry{pt.Link("bin", "usr/bin"), pt.Link("lib64", "usr/lib64")}, bin...)
	return append(append(e, ld), pt.BootLayout()...)
}

// TestShellExecPrecedence pins where shell_not_executable sits relative to
// the other shell and interpreter findings: earlier shell failures return
// with only their own finding; on a valid ELF it is added and the dynamic
// interpreter checks still run afterwards; the interpreter's own mode and a
// link's own mode are never consulted; the resolved file's mode is.
func TestShellExecPrecedence(t *testing.T) {
	const sh = "usr/bin/sh"
	dyn := pt.ELF(pt.EMX8664, pt.Loader)
	ld := "usr/lib64/ld-linux-x86-64.so.2"
	entry := func(e pt.Entry) *pt.Entry { return &e }
	ne := Finding{"shell_not_executable", ShellPath, noExecDetail("0644")}
	for _, tc := range []struct {
		name    string
		entries []pt.Entry
		want    []string
		first   *Finding // exact first finding when set
	}{
		{"noexec script stays elf_invalid", shellTree(nil, pt.FileMode(sh, []byte("#!/bin/dash\n"), 0o644)), []string{"elf_invalid"}, nil},
		{"noexec empty stays elf_invalid", shellTree(nil, pt.FileMode(sh, nil, 0o644)), []string{"elf_invalid"}, nil},
		{"noexec aarch64 stays arch_unsupported", shellTree(nil, pt.FileMode(sh, pt.ELF(pt.EMAArch64, "/lib/ld-linux-aarch64.so.1"), 0o644)),
			[]string{"arch_unsupported"}, nil},
		{"noexec then interp_elf_invalid", shellTree(entry(pt.File(ld, []byte("synthetic loader placeholder"))), pt.FileMode(sh, dyn, 0o644)),
			[]string{"shell_not_executable", "interp_elf_invalid"}, &ne},
		{"noexec then interp type", shellTree(entry(pt.File(ld, pt.TypedHeader(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664, pt.ETRel))),
			pt.FileMode(sh, dyn, 0o644)), []string{"shell_not_executable", "interp_elf_invalid"}, &ne},
		{"noexec then interp arch", shellTree(entry(pt.File(ld, pt.Header(pt.ELFClass64, pt.ELFDataLSB, pt.EMAArch64))),
			pt.FileMode(sh, dyn, 0o644)), []string{"shell_not_executable", "interp_arch_unsupported"}, &ne},
		{"noexec then interp_not_regular", shellTree(entry(pt.FIFO(ld)), pt.FileMode(sh, dyn, 0o644)),
			[]string{"shell_not_executable", "interp_not_regular"}, &ne},
		{"noexec mode 0600", shellTree(nil, pt.FileMode(sh, dyn, 0o600)), []string{"shell_not_executable"},
			&Finding{"shell_not_executable", ShellPath, noExecDetail("0600")}},
		{"noexec mode 0444", shellTree(nil, pt.FileMode(sh, dyn, 0o444)), []string{"shell_not_executable"},
			&Finding{"shell_not_executable", ShellPath, noExecDetail("0444")}},
		{"interp mode not checked", shellTree(entry(pt.FileMode(ld, pt.LoaderELF(), 0o644)), pt.File(sh, dyn)), []string{}, nil},
		{"link to noexec target", shellTree(nil, pt.FileMode("usr/bin/dash", dyn, 0o644), pt.Link(sh, "dash")),
			[]string{"shell_not_executable"}, &ne},
		{"link to exec target", shellTree(nil, pt.FileMode("usr/bin/dash", dyn, 0o755), pt.Link(sh, "dash")), []string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runCheck(t, build(t, tc.entries...))
			if err != nil {
				t.Fatal(err)
			}
			if got := codes(r); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("codes = %v; want %v (%+v)", got, tc.want, r.Findings)
			}
			if tc.first != nil && (len(r.Findings) == 0 || r.Findings[0] != *tc.first) {
				t.Errorf("first finding = %+v; want %+v", r.Findings, *tc.first)
			}
			for _, f := range r.Findings[min(1, len(r.Findings)):] {
				if f.Code == "shell_not_executable" {
					t.Errorf("shell_not_executable not first or repeated: %+v", r.Findings)
				}
			}
			if len(tc.want) > 0 && tc.want[0] == "shell_not_executable" && r.Interp != pt.Loader {
				t.Errorf("Interp = %q; want %q (dynamic checks must continue)", r.Interp, pt.Loader)
			}
		})
	}
}

// TestShellExecWithBootFindings shows the shell and /boot checks stay
// independent: a non-executable shell and a missing /boot both report.
func TestShellExecWithBootFindings(t *testing.T) {
	root := build(t, pt.Link("bin", "usr/bin"), pt.Link("lib64", "usr/lib64"),
		pt.FileMode("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader), 0o644),
		pt.File("usr/lib64/ld-linux-x86-64.so.2", pt.LoaderELF()))
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := pairs(r); !reflect.DeepEqual(got, []pt.FindingPair{{Code: "shell_not_executable", Path: ShellPath}, {Code: "kernel_missing", Path: BootDir}}) {
		t.Errorf("pairs = %v", got)
	}
}

// TestShellUnreadableStaysReadError: a shell at mode 000 cannot be read by a
// nonprivileged runner, so it keeps exactly its read_error finding and gets
// no permission finding.
func TestShellUnreadableStaysReadError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not deny root")
	}
	root := build(t, shellTree(nil, pt.FileMode("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader), 0))...)
	sh := filepath.Join(root, "usr/bin/sh")
	t.Cleanup(func() { _ = os.Chmod(sh, 0o755) })
	if fi, err := os.Lstat(sh); err != nil || fi.Mode().Perm() != 0 {
		t.Fatalf("fixture shell mode = %v (%v); want 000", fi, err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Code != "read_error" || r.Findings[0].Path != ShellPath ||
		!strings.HasPrefix(r.Findings[0].Detail, "cannot read: ") {
		t.Errorf("findings = %#v; want exactly one read_error at %s", r.Findings, ShellPath)
	}
}

// TestFixtureMode pins the optional fixture mode: absent keeps the default
// creation path, present is applied exactly (even 000 and bits the umask
// would remove), and it is refused for every non-regular kind and for
// outside-root sentinels.
func TestFixtureMode(t *testing.T) {
	root := t.TempDir()
	if err := pt.Build(root, pt.File("plain", []byte("x")), pt.FileMode("m644", []byte("x"), 0o644),
		pt.FileMode("m000", []byte("x"), 0), pt.FileMode("m777", []byte("x"), 0o777)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "m000"), 0o644) })
	if pt.File("plain", nil).Mode != nil {
		t.Error("File sets a Mode; absence must mean the default")
	}
	ref := filepath.Join(t.TempDir(), "ref")
	if err := os.WriteFile(ref, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	refInfo, err := os.Lstat(ref)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]fs.FileMode{"plain": refInfo.Mode(), "m644": 0o644, "m000": 0, "m777": 0o777} {
		fi, err := os.Lstat(filepath.Join(root, name))
		if err != nil || fi.Mode() != want {
			t.Errorf("%s mode = %v (%v); want %v", name, fi, err, want)
		}
	}
	m := fs.FileMode(0o644)
	for _, e := range []pt.Entry{
		{Path: "l", Kind: pt.KindLink, Target: "plain", Mode: &m},
		{Path: "d", Kind: pt.KindDir, Mode: &m},
		{Path: "f", Kind: pt.KindFIFO, Mode: &m},
	} {
		dir := t.TempDir()
		if err := pt.Build(dir, e); err == nil {
			t.Errorf("Build accepted Mode on kind %d", e.Kind)
		}
		if _, err := os.Lstat(filepath.Join(dir, e.Path)); !os.IsNotExist(err) {
			t.Errorf("kind %d: entry created despite refused Mode (%v)", e.Kind, err)
		}
	}
	if err := pt.Build(t.TempDir(), pt.FileMode("s", nil, 0o4755)); err == nil {
		t.Error("Build accepted a mode with non-permission bits")
	}
	sandbox := t.TempDir()
	fx := pt.Fixture{Name: "x", Outside: []pt.Entry{pt.FileMode("sentinel", []byte("s"), 0o600)}}
	if _, err := pt.BuildFixture(sandbox, fx); err == nil {
		t.Error("BuildFixture accepted a Mode on an outside sentinel")
	}
	if _, err := os.Lstat(filepath.Join(sandbox, "sentinel")); !os.IsNotExist(err) {
		t.Errorf("outside sentinel created despite refused Mode (%v)", err)
	}
}
