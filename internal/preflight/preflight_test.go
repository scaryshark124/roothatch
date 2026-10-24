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

func TestCatalog(t *testing.T) {
	for _, fx := range pt.Catalog() {
		t.Run(fx.Name, func(t *testing.T) {
			root := build(t, fx.Entries...)
			before, err := pt.Digest(root)
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
			after, err := pt.Digest(root)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("fixture tree changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
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
		pt.File("usr/lib64/ld-linux-x86-64.so.2", []byte("loader"))}, extra...)
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
				pt.Link("lib64", "usr/lib64"), pt.File("usr/lib64/ld-linux-x86-64.so.2", []byte("x"))}, pt.BootLayout()...)...)
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
