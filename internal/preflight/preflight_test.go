package preflight

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// runCheck runs Check with a deadline so FIFOs or loops cannot hang the suite.
func runCheck(t *testing.T, dir string) (Report, error) {
	t.Helper()
	type res struct {
		r   Report
		err error
	}
	ch := make(chan res, 1)
	go func() {
		r, err := Check(dir)
		ch <- res{r, err}
	}()
	select {
	case v := <-ch:
		return v.r, v.err
	case <-time.After(10 * time.Second):
		t.Fatal("Check did not return within 10s")
		return Report{}, nil
	}
}

func codes(r Report) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func build(t *testing.T, entries ...pt.Entry) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := pt.Build(root, entries...); err != nil {
		t.Fatal(err)
	}
	return root
}

// pairs returns the (code, path) pairs of r's findings in report order.
func pairs(r Report) []pt.FindingPair {
	out := []pt.FindingPair{}
	for _, f := range r.Findings {
		out = append(out, pt.FindingPair{Code: f.Code, Path: f.Path})
	}
	return out
}

// pairCounts is a multiset of (code, path) pairs; duplicates are counted.
func pairCounts(ps []pt.FindingPair) map[pt.FindingPair]int {
	m := map[pt.FindingPair]int{}
	for _, p := range ps {
		m[p]++
	}
	return m
}

// checkFindingPairs asserts fx.Findings, when set, as an exact multiset and
// as the exact report order, and that it agrees with fx.Want.
func checkFindingPairs(t *testing.T, fx pt.Fixture, r Report) {
	t.Helper()
	if fx.Findings == nil {
		return
	}
	wantCodes := []string{}
	for _, p := range fx.Findings {
		wantCodes = append(wantCodes, p.Code)
	}
	if !reflect.DeepEqual(wantCodes, append([]string{}, fx.Want...)) {
		t.Fatalf("fixture inconsistent: Findings codes %v != Want %v", wantCodes, fx.Want)
	}
	got := pairs(r)
	if !reflect.DeepEqual(pairCounts(got), pairCounts(fx.Findings)) {
		t.Errorf("(code, path) multiset = %v; want %v (findings %+v)", got, fx.Findings, r.Findings)
	}
	if !reflect.DeepEqual(got, fx.Findings) {
		t.Errorf("(code, path) order = %v; want %v", got, fx.Findings)
	}
}

func TestCatalog(t *testing.T) {
	for _, fx := range pt.Catalog() {
		t.Run(fx.Name, func(t *testing.T) {
			sandbox := t.TempDir()
			root, err := pt.BuildFixture(sandbox, fx)
			if err != nil {
				t.Fatal(err)
			}
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatalf("Check error: %v", err)
			}
			want := fx.Want
			if want == nil {
				want = []string{}
			}
			if got := codes(r); !reflect.DeepEqual(got, want) {
				t.Errorf("codes = %v; want %v (findings %+v)", got, want, r.Findings)
			}
			checkFindingPairs(t, fx, r)
			if r.Static != fx.Static {
				t.Errorf("Static = %v; want %v", r.Static, fx.Static)
			}
			if len(want) == 0 && !fx.Static && r.Interp != pt.Loader {
				t.Errorf("Interp = %q; want %q", r.Interp, pt.Loader)
			}
			if got, wantK := append([]string{}, r.Kernels...), append([]string{}, fx.Kernels...); !reflect.DeepEqual(got, wantK) {
				t.Errorf("Kernels = %v; want %v", got, wantK)
			}
			present := []string{}
			for _, l := range r.Links {
				if l.Present {
					present = append(present, l.Path)
				}
			}
			if wantS := append([]string{}, fx.Shortcuts...); !reflect.DeepEqual(present, wantS) {
				t.Errorf("present shortcuts = %v; want %v (links %+v)", present, wantS, r.Links)
			}
			if len(r.Links) != len(ShortcutLinks) {
				t.Errorf("Links = %+v; want one status per shortcut %v", r.Links, ShortcutLinks)
			}
			after, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("fixture tree changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// TestKernelEscapeDetails pins the escape finding's path and resolver detail,
// that an escaping candidate is never counted or given an initrd check, and
// that kernel_missing keeps its existing detail including the ignored count.
func TestKernelEscapeDetails(t *testing.T) {
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	v := pt.KernelVersion
	for _, tc := range []struct {
		name string
		want []Finding
		kern []string
	}{
		{"boot_kernel_escape", []Finding{
			{"symlink_escape", "/boot/vmlinuz-" + v, `symlink /boot/vmlinuz-` + v + ` -> "../../outside-kernel" leads outside the root; not followed`},
			{"kernel_missing", "/boot", "no vmlinuz-<version> kernel in /boot (Debian naming convention consistency check; not a bootability verdict)" +
				"; 1 vmlinuz-* entr(y/ies) ignored (empty version or not a regular file inside the root)"},
		}, nil},
		{"boot_kernel_escape_with_valid_pair", []Finding{
			{"symlink_escape", "/boot/vmlinuz-6.9.0-esc", `symlink /boot/vmlinuz-6.9.0-esc -> "../../sentinel" leads outside the root; not followed`},
		}, []string{v}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := pt.BuildFixture(t.TempDir(), cat[tc.name])
			if err != nil {
				t.Fatal(err)
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Findings, tc.want) {
				t.Errorf("findings = %#v\nwant %#v", r.Findings, tc.want)
			}
			if !reflect.DeepEqual(append([]string{}, r.Kernels...), append([]string{}, tc.kern...)) {
				t.Errorf("Kernels = %v; want %v", r.Kernels, tc.kern)
			}
		})
	}
	// The absolute "/../../<host path>" style is refused at the root even
	// though the same target reaches the sentinel on the host.
	sandbox := t.TempDir()
	root, err := pt.BuildFixture(sandbox, cat["boot_two_kernel_escapes_with_valid_pair"])
	if err != nil {
		t.Fatal(err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || !strings.HasPrefix(r.Findings[0].Detail, "symlink /boot/vmlinuz-7.0-abs -> \"/../../") ||
		!strings.HasSuffix(r.Findings[0].Detail, "/sentinel-abs\" leads outside the root; not followed") ||
		r.Findings[1].Detail != `symlink /boot/vmlinuz-9.0-rel -> "../../sentinel-rel" leads outside the root; not followed` {
		t.Errorf("findings = %#v", r.Findings)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, "must never be read") {
			t.Errorf("sentinel content leaked: %+v", f)
		}
	}
	for _, name := range []string{"vmlinuz-7.0-abs", "vmlinuz-9.0-rel"} {
		host, err := os.Stat(filepath.Join(root, "boot", name))
		if err != nil {
			t.Fatalf("host resolution of %s: %v", name, err)
		}
		want, err := os.Stat(filepath.Join(sandbox, "sentinel-"+name[len(name)-3:]))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(host, want) {
			t.Errorf("%s does not reach its outside sentinel on the host; fixture is not a genuine escape", name)
		}
	}
}

// TestInitrdEscapeDetails pins the initrd escape finding's path and resolver
// detail, that initrd_missing keeps its existing detail built from the same
// failure, that the kernel stays counted, and that both the relative and the
// absolute "/../../<host path>" links genuinely reach their host sentinels.
func TestInitrdEscapeDetails(t *testing.T) {
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	v := pt.KernelVersion
	missing := func(ver, detail string) string {
		return "kernel version " + ver + " has no matching initrd.img-" + ver + " regular file inside the root: " + detail +
			" (Debian naming convention consistency check; not a bootability verdict)"
	}
	escape := func(ver, target string) string {
		return `symlink /boot/initrd.img-` + ver + ` -> "` + target + `" leads outside the root; not followed`
	}
	for _, tc := range []struct {
		name string
		want []Finding
		kern []string
	}{
		{"boot_initrd_escape", []Finding{
			{"symlink_escape", "/boot/initrd.img-" + v, escape(v, "../../outside-initrd")},
			{"initrd_missing", "/boot/initrd.img-" + v, missing(v, escape(v, "../../outside-initrd"))},
		}, []string{v}},
		{"boot_initrd_escape_with_valid_pair", []Finding{
			{"symlink_escape", "/boot/initrd.img-6.9.0-esc", escape("6.9.0-esc", "../../sentinel-initrd")},
			{"initrd_missing", "/boot/initrd.img-6.9.0-esc", missing("6.9.0-esc", escape("6.9.0-esc", "../../sentinel-initrd"))},
		}, []string{v, "6.9.0-esc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := pt.BuildFixture(t.TempDir(), cat[tc.name])
			if err != nil {
				t.Fatal(err)
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Findings, tc.want) {
				t.Errorf("findings = %#v\nwant %#v", r.Findings, tc.want)
			}
			if !reflect.DeepEqual(append([]string{}, r.Kernels...), tc.kern) {
				t.Errorf("Kernels = %v; want %v", r.Kernels, tc.kern)
			}
		})
	}
	sandbox := t.TempDir()
	root, err := pt.BuildFixture(sandbox, cat["boot_two_initrd_escapes"])
	if err != nil {
		t.Fatal(err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 4 || !strings.HasPrefix(r.Findings[0].Detail, `symlink /boot/initrd.img-7.0-abs -> "/../../`) ||
		!strings.HasSuffix(r.Findings[0].Detail, `/y" leads outside the root; not followed`) ||
		r.Findings[1].Detail != missing("7.0-abs", r.Findings[0].Detail) ||
		r.Findings[2].Detail != escape("9.0-rel", "../../x") ||
		r.Findings[3].Detail != missing("9.0-rel", escape("9.0-rel", "../../x")) {
		t.Errorf("findings = %#v", r.Findings)
	}
	if !reflect.DeepEqual(append([]string{}, r.Kernels...), []string{"7.0-abs", "9.0-rel"}) {
		t.Errorf("Kernels = %v; want [7.0-abs 9.0-rel]", r.Kernels)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, "must never be read") {
			t.Errorf("sentinel content leaked: %+v", f)
		}
	}
	for name, sentinel := range map[string]string{"initrd.img-7.0-abs": "y", "initrd.img-9.0-rel": "x"} {
		host, err := os.Stat(filepath.Join(root, "boot", name))
		if err != nil {
			t.Fatalf("host resolution of %s: %v", name, err)
		}
		want, err := os.Stat(filepath.Join(sandbox, sentinel))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(host, want) {
			t.Errorf("%s does not reach its outside sentinel on the host; fixture is not a genuine escape", name)
		}
	}
}

func TestRootErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{file, filepath.Join(t.TempDir(), "absent")} {
		_, err := Check(dir)
		var re *RootError
		if !errors.As(err, &re) {
			t.Errorf("Check(%q) error = %v; want *RootError", dir, err)
		}
	}
}

// TestEscapeNeverReadsHost places a distinctive ELF outside the root at the
// path an escaping link names. Reading it would report its interpreter.
func TestEscapeNeverReadsHost(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	const secret = "/outside/secret-interp"
	if err := pt.Build(base, pt.File("outside/sh", pt.ELF(pt.EMX8664, secret))); err != nil {
		t.Fatal(err)
	}
	if err := pt.Build(root, append([]pt.Entry{pt.Link("bin", "usr/bin"), pt.Link("usr/bin/sh", "../../../outside/sh")}, pt.BootLayout()...)...); err != nil {
		t.Fatal(err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(r); !reflect.DeepEqual(got, []string{"symlink_escape"}) {
		t.Fatalf("codes = %v; want [symlink_escape]", got)
	}
	if r.Interp != "" || strings.Contains(r.Findings[0].Detail, "secret") {
		t.Fatalf("outside file was read: %+v", r)
	}
}

// healthyWith returns a healthy shell/interpreter tree plus extra entries.
func healthyWith(extra ...pt.Entry) []pt.Entry {
	return append([]pt.Entry{pt.Link("bin", "usr/bin"), pt.Link("lib64", "usr/lib64"),
		pt.File("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader)),
		pt.File("usr/lib64/ld-linux-x86-64.so.2", pt.LoaderELF())}, extra...)
}

// TestBootEscapeNeverReadsHost points /boot at an outside directory holding a
// valid-looking kernel layout. Following it would report that kernel.
func TestBootEscapeNeverReadsHost(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := pt.Build(base, pt.File("outside-boot/vmlinuz-secret", []byte("k")),
		pt.File("outside-boot/initrd.img-secret", []byte("i"))); err != nil {
		t.Fatal(err)
	}
	if err := pt.Build(root, healthyWith(pt.Link("boot", "../outside-boot"),
		pt.Link("vmlinuz", "../outside-boot/vmlinuz-secret"))...); err != nil {
		t.Fatal(err)
	}
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(r); !reflect.DeepEqual(got, []string{"symlink_escape", "symlink_escape"}) {
		t.Fatalf("codes = %v; want [symlink_escape symlink_escape] (%+v)", got, r.Findings)
	}
	if len(r.Kernels) != 0 {
		t.Fatalf("outside kernels reported: %v", r.Kernels)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Path, "secret") && f.Path != "/vmlinuz" {
			t.Fatalf("outside entry name leaked: %+v", f)
		}
	}
}

// TestBootEnumerationBound accepts exactly maxBootEntries entries and reports
// a read_error, never a healthy result, when /boot holds more.
func TestBootEnumerationBound(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want []string
	}{{maxBootEntries, []string{}}, {maxBootEntries + 1, []string{"read_error"}}} {
		entries := healthyWith(pt.BootLayout()...)
		for i := len(entries); len(entries)-4 < tc.n; i++ {
			entries = append(entries, pt.File(fmt.Sprintf("boot/filler-%05d", i), nil))
		}
		root := build(t, entries...)
		r, err := runCheck(t, root)
		if err != nil {
			t.Fatal(err)
		}
		if got := codes(r); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%d entries: codes = %v; want %v (%+v)", tc.n, got, tc.want, r.Findings)
		}
		if len(tc.want) != 0 && (len(r.Kernels) != 0 || r.Findings[0].Path != "/boot") {
			t.Errorf("%d entries: overflow must not report kernels: %+v", tc.n, r)
		}
	}
}

// TestBootUnreadable reports read_error for a /boot that cannot be listed.
func TestBootUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not deny root")
	}
	root := build(t, healthyWith(pt.BootLayout()...)...)
	boot := filepath.Join(root, "boot")
	if err := os.Chmod(boot, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(boot, 0o755) })
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(r); !reflect.DeepEqual(got, []string{"read_error"}) || r.Findings[0].Path != "/boot" {
		t.Errorf("codes = %v; want [read_error] for /boot (%+v)", got, r.Findings)
	}
	if len(r.Kernels) != 0 {
		t.Errorf("unreadable /boot reported kernels %v", r.Kernels)
	}
}

// TestBootFindingDetails pins the Debian-convention wording and the
// per-version initrd path.
func TestBootFindingDetails(t *testing.T) {
	root := build(t, healthyWith(pt.File("boot/vmlinuz-6.2.0-x", []byte("k")))...)
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Path != "/boot/initrd.img-6.2.0-x" ||
		!strings.Contains(r.Findings[0].Detail, "Debian") || !strings.Contains(r.Findings[0].Detail, "6.2.0-x") {
		t.Errorf("initrd finding = %+v", r.Findings)
	}
	root = build(t, healthyWith(pt.Dir("boot"))...)
	r, err = runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Path != "/boot" || !strings.Contains(r.Findings[0].Detail, "Debian naming") {
		t.Errorf("kernel finding = %+v", r.Findings)
	}
}

// TestSwapRaceNeverReadsHost swaps /usr/bin/sh between a valid shell and an
// escaping link while Check runs; any result may be reported, but never data
// from the outside file.
func TestSwapRaceNeverReadsHost(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	const secret = "/outside/secret-interp"
	if err := pt.Build(base, pt.File("outside/sh", pt.ELF(pt.EMX8664, secret))); err != nil {
		t.Fatal(err)
	}
	if err := pt.Build(root, pt.Link("bin", "usr/bin"), pt.File("usr/bin/good", pt.ELF(pt.EMX8664, pt.Loader)),
		pt.Link("usr/bin/bad", "../../../outside/sh"), pt.File("usr/bin/sh", pt.ELF(pt.EMX8664, pt.Loader))); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		bin := filepath.Join(root, "usr/bin")
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			src := "good"
			if i%2 == 0 {
				src = "bad"
			}
			_ = os.Remove(filepath.Join(bin, "tmp"))
			if i%2 == 0 {
				_ = os.Symlink("../../../outside/sh", filepath.Join(bin, "tmp"))
			} else {
				_ = os.Link(filepath.Join(bin, src), filepath.Join(bin, "tmp"))
			}
			_ = os.Rename(filepath.Join(bin, "tmp"), filepath.Join(bin, "sh"))
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 300; i++ {
		r, err := runCheck(t, root)
		if err != nil {
			t.Fatal(err)
		}
		if r.Interp == secret {
			t.Fatalf("iteration %d read outside file: %+v", i, r)
		}
		for _, f := range r.Findings {
			if strings.Contains(f.Detail, "secret") {
				t.Fatalf("iteration %d leaked outside data: %+v", i, f)
			}
		}
	}
}

// mutate returns a valid shell ELF modified by fn.
func mutate(fn func(b []byte) []byte) []byte {
	return fn(pt.ELF(pt.EMX8664, pt.Loader))
}

func TestMalformedELF(t *testing.T) {
	le := binary.LittleEndian
	interpPh := 64 + 56 // second program header
	cases := map[string][]byte{
		"bad magic":            mutate(func(b []byte) []byte { b[1] = 'X'; return b }),
		"bad ident version":    mutate(func(b []byte) []byte { b[6] = 9; return b }),
		"short header":         mutate(func(b []byte) []byte { return b[:63] }),
		"bad e_type":           mutate(func(b []byte) []byte { le.PutUint16(b[16:], 1); return b }),
		"no program headers":   mutate(func(b []byte) []byte { le.PutUint16(b[56:], 0); return b }),
		"pn_xnum":              mutate(func(b []byte) []byte { le.PutUint16(b[56:], 0xffff); return b }),
		"small phentsize":      mutate(func(b []byte) []byte { le.PutUint16(b[54:], 8); return b }),
		"huge phoff":           mutate(func(b []byte) []byte { le.PutUint64(b[32:], ^uint64(0)-4); return b }),
		"phdr table truncated": mutate(func(b []byte) []byte { return b[:64+56+20] }),
		"phnum overflows file": mutate(func(b []byte) []byte { le.PutUint16(b[56:], 5000); return b }),
		"interp huge offset":   mutate(func(b []byte) []byte { le.PutUint64(b[interpPh+8:], ^uint64(0)-1); return b }),
		"interp huge size":     mutate(func(b []byte) []byte { le.PutUint64(b[interpPh+32:], ^uint64(0)); return b }),
		"interp over cap":      mutate(func(b []byte) []byte { le.PutUint64(b[interpPh+32:], 1<<20); return b }),
		"interp no nul":        mutate(func(b []byte) []byte { b[len(b)-1] = 'x'; return b }),
		"interp embedded nul":  mutate(func(b []byte) []byte { b[len(b)-5] = 0; return b }),
		"interp empty":         mutate(func(b []byte) []byte { le.PutUint64(b[interpPh+32:], 1); b[64+112] = 0; return b }),
		"interp relative":      mutate(func(b []byte) []byte { b[64+112] = 'x'; return b }),
		"interp truncated":     mutate(func(b []byte) []byte { return b[:len(b)-4] }),
		"duplicate interp": mutate(func(b []byte) []byte {
			copy(b[64:64+56], b[interpPh:interpPh+56])
			return b
		}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			root := build(t, append([]pt.Entry{pt.Link("bin", "usr/bin"), pt.File("usr/bin/sh", data),
				pt.Link("lib64", "usr/lib64"), pt.File("usr/lib64/ld-linux-x86-64.so.2", pt.LoaderELF())}, pt.BootLayout()...)...)
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if got := codes(r); !reflect.DeepEqual(got, []string{"elf_invalid"}) {
				t.Errorf("codes = %v; want [elf_invalid] (%+v)", got, r.Findings)
			}
		})
	}
}

func FuzzShellBytes(f *testing.F) {
	f.Add(pt.ELF(pt.EMX8664, pt.Loader))
	f.Add(pt.ELF(pt.EMX8664, ""))
	f.Add(pt.ELF(pt.EMAArch64, "/x"))
	f.Add([]byte("\x7fELF\x02\x01\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := filepath.Join(t.TempDir(), "root")
		if err := pt.Build(root, pt.Link("bin", "usr/bin"), pt.File("usr/bin/sh", data)); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root); err != nil {
			t.Fatal(err)
		}
	})
}

// interpNoteWant is the suffix of every interpreter header finding.
const interpNoteWant = " (header-level check of the interpreter only; not a verdict that the loader works)"

// TestInterpHeaderDetails pins the finding path (the PT_INTERP string, not the
// resolved target) and the exact header-level detail of every interpreter
// header fixture, and that the PASS controls report the interpreter.
func TestInterpHeaderDetails(t *testing.T) {
	want := map[string][]Finding{
		"interp_elf_text":              {{"interp_elf_invalid", pt.Loader, "not an ELF file" + interpNoteWant}},
		"interp_elf_empty":             {{"interp_elf_invalid", pt.Loader, "not an ELF file" + interpNoteWant}},
		"interp_elf_truncated_elf64":   {{"interp_elf_invalid", pt.Loader, "truncated ELF64 header (63 bytes; want 64)" + interpNoteWant}},
		"interp_elf_bad_class":         {{"interp_elf_invalid", pt.Loader, "invalid ELF class 3" + interpNoteWant}},
		"interp_elf_bad_data":          {{"interp_elf_invalid", pt.Loader, "invalid ELF data encoding 3" + interpNoteWant}},
		"interp_elf_bad_ident_version": {{"interp_elf_invalid", pt.Loader, "unsupported ELF identification version 2" + interpNoteWant}},
		"interp_elf_truncated_elf32":   {{"interp_elf_invalid", pt.Loader, "truncated ELF32 header (51 bytes; want 52)" + interpNoteWant}},
		"interp_arch_aarch64": {{"interp_arch_unsupported", pt.Loader,
			"interpreter is ELF64 little-endian machine 183 (AArch64); want ELF64 little-endian x86-64 (62)" + interpNoteWant}},
		"interp_arch_elf32_i386": {{"interp_arch_unsupported", pt.Loader,
			"interpreter is ELF32 little-endian machine 3 (i386); want ELF64 little-endian x86-64 (62)" + interpNoteWant}},
		"interp_arch_elf64_big_endian": {{"interp_arch_unsupported", pt.Loader,
			"interpreter is ELF64 big-endian machine 62 (x86-64); want ELF64 little-endian x86-64 (62)" + interpNoteWant}},
		"interp_link_relative_in_tree": nil,
		"interp_link_absolute_in_tree": nil,
		"interp_large_valid_header":    nil,
	}
	seen := 0
	for _, fx := range pt.InterpCatalog() {
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
			if fx.Name == "interp_large_valid_header" {
				fi, err := os.Stat(filepath.Join(root, "usr/lib64/ld-linux-x86-64.so.2"))
				if err != nil || fi.Size() != pt.LargeLoaderSize || fi.Size() <= elfPrefix {
					t.Fatalf("large loader size = %v (%v); want %d > %d", fi, err, pt.LargeLoaderSize, elfPrefix)
				}
			}
			r, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.Findings, w) {
				t.Errorf("findings = %#v\nwant %#v", r.Findings, w)
			}
			if r.Interp != pt.Loader || r.Static {
				t.Errorf("Interp = %q Static = %v; want %q, false", r.Interp, r.Static, pt.Loader)
			}
		})
	}
	if seen != len(want) {
		t.Errorf("InterpCatalog has %d of %d pinned fixtures", seen, len(want))
	}
}

// TestInterpUnreadable reports read_error at the PT_INTERP path when the
// regular interpreter cannot be read; nothing else is reported.
func TestInterpUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not deny root")
	}
	root := build(t, healthyWith(pt.BootLayout()...)...)
	ld := filepath.Join(root, "usr/lib64/ld-linux-x86-64.so.2")
	if err := os.Chmod(ld, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ld, 0o755) })
	r, err := runCheck(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Code != "read_error" || r.Findings[0].Path != pt.Loader ||
		!strings.HasPrefix(r.Findings[0].Detail, "cannot read: ") {
		t.Errorf("findings = %#v; want one read_error at %s with \"cannot read: \" detail", r.Findings, pt.Loader)
	}
}

// TestInterpHeaderBoundary pins the helper's narrow boundary: only ident,
// class-specific header length, e_machine and e_type matter. Other header
// fields, even hostile table offsets/counts, and trailing bytes are ignored.
func TestInterpHeaderBoundary(t *testing.T) {
	le := binary.LittleEndian
	ok := func(fn func(b []byte) []byte) []byte {
		return fn(pt.Header(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664))
	}
	for name, b := range map[string][]byte{
		"bare header":       ok(func(b []byte) []byte { return b }),
		"e_version 0":       ok(func(b []byte) []byte { le.PutUint32(b[20:], 0); return b }),
		"OS ABI 97":         ok(func(b []byte) []byte { b[7] = 97; return b }),
		"huge phoff/phnum":  ok(func(b []byte) []byte { le.PutUint64(b[32:], ^uint64(0)); le.PutUint16(b[56:], 0xffff); return b }),
		"huge shoff/shnum":  ok(func(b []byte) []byte { le.PutUint64(b[40:], ^uint64(0)); le.PutUint16(b[60:], 0xffff); return b }),
		"trailing bytes":    ok(func(b []byte) []byte { return append(b, make([]byte, 4096)...) }),
		"full ELF64 loader": pt.LoaderELF(),
	} {
		if p := interpHeader(b); p != nil {
			t.Errorf("%s: %+v; want pass", name, p)
		}
	}
	for name, tc := range map[string]struct {
		b    []byte
		code string
	}{
		"15 bytes":               {pt.Header(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664)[:15], "interp_elf_invalid"},
		"16 bytes ELF64":         {pt.Header(pt.ELFClass64, pt.ELFDataLSB, pt.EMX8664)[:16], "interp_elf_invalid"},
		"bad magic":              {ok(func(b []byte) []byte { b[3] = 'X'; return b }), "interp_elf_invalid"},
		"class 0":                {ok(func(b []byte) []byte { b[4] = 0; return b }), "interp_elf_invalid"},
		"data 0":                 {ok(func(b []byte) []byte { b[5] = 0; return b }), "interp_elf_invalid"},
		"ELF32 BE truncated":     {pt.Header(pt.ELFClass32, pt.ELFDataMSB, pt.EMX8664)[:51], "interp_elf_invalid"},
		"ELF32 full x86-64":      {pt.Header(pt.ELFClass32, pt.ELFDataLSB, pt.EMX8664), "interp_arch_unsupported"},
		"ELF32 BE MIPS":          {pt.Header(pt.ELFClass32, pt.ELFDataMSB, 8), "interp_arch_unsupported"},
		"ELF64 LE unknown 65535": {pt.Header(pt.ELFClass64, pt.ELFDataLSB, 0xffff), "interp_arch_unsupported"},
		"e_type ET_REL":          {ok(func(b []byte) []byte { le.PutUint16(b[16:], 1); return b }), "interp_elf_invalid"},
	} {
		p := interpHeader(tc.b)
		if p == nil || p.code != tc.code || !strings.HasSuffix(p.detail, interpNoteWant) {
			t.Errorf("%s: %+v; want %s with header-level note", name, p, tc.code)
		}
	}
	if p := interpHeader(pt.Header(pt.ELFClass32, pt.ELFDataMSB, 8)); p == nil ||
		!strings.HasPrefix(p.detail, "interpreter is ELF32 big-endian machine 8 (MIPS);") {
		t.Errorf("big-endian e_machine not decoded in declared order: %+v", p)
	}
	if p := interpHeader(ok(func(b []byte) []byte { le.PutUint16(b[16:], 1); return b })); p == nil ||
		!strings.HasPrefix(p.detail, "ELF type 1 (ET_REL) is not an executable or shared object") {
		t.Errorf("ET_REL detail: %+v", p)
	}
	if p := interpHeader(pt.Header(pt.ELFClass64, pt.ELFDataLSB, 0xffff)); p == nil ||
		!strings.HasPrefix(p.detail, "interpreter is ELF64 little-endian machine 65535 (unknown);") {
		t.Errorf("unknown machine detail: %+v", p)
	}
}
