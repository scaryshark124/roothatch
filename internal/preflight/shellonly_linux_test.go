//go:build linux

package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// runCheckShell runs CheckShell with a deadline so FIFOs or loops cannot hang
// the suite.
func runCheckShell(t *testing.T, dir string) (Report, error) {
	t.Helper()
	type res struct {
		r   Report
		err error
	}
	ch := make(chan res, 1)
	go func() {
		r, err := CheckShell(dir)
		ch <- res{r, err}
	}()
	select {
	case v := <-ch:
		return v.r, v.err
	case <-time.After(10 * time.Second):
		t.Fatal("CheckShell did not return within 10s")
		return Report{}, nil
	}
}

// shellPortion is the reference oracle for this test only: the report the
// existing checkShell phase alone produces, obtained by calling checkShell
// directly on an admitted root descriptor (never by filtering Check).
func shellPortion(t *testing.T, dir string) Report {
	t.Helper()
	fd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var r Report
	checkShell(fd, &r)
	return r
}

// TestCheckShellEqualsShellPortion: on representative fixtures (passing,
// shell failures, boot failures, both), CheckShell returns exactly the report
// of the checkShell phase, which is also the leading part of Check's findings
// with the same Interp/Static, and no Kernels or Links.
func TestCheckShellEqualsShellPortion(t *testing.T) {
	var fxs []pt.Fixture
	for _, f := range pt.ShellOnlyCatalog() {
		fxs = append(fxs, f.Fixture())
	}
	fxs = append(fxs, pt.Catalog()...)
	fxs = append(fxs, pt.EscapeCatalog()...)
	for _, fx := range fxs {
		if fx.Name == "fifo_shell" || fx.Name == "fifo_interp" {
			continue // covered by the timeout helper elsewhere; nothing shell-only specific
		}
		t.Run(fx.Name, func(t *testing.T) {
			_, root := buildFixture(t, fx)
			got, err := runCheckShell(t, root)
			if err != nil {
				t.Fatal(err)
			}
			want := shellPortion(t, root)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("CheckShell = %+v; want checkShell portion %+v", got, want)
			}
			if got.Kernels != nil || got.Links != nil {
				t.Errorf("CheckShell ran boot/shortcut phases: Kernels %v Links %v", got.Kernels, got.Links)
			}
			full, err := runCheck(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if len(full.Findings) < len(got.Findings) ||
				!reflect.DeepEqual(append([]Finding{}, full.Findings[:len(got.Findings)]...), append([]Finding{}, got.Findings...)) {
				t.Errorf("CheckShell findings %+v are not the leading shell findings of Check %+v", got.Findings, full.Findings)
			}
			if full.Interp != got.Interp || full.Static != got.Static {
				t.Errorf("Interp/Static = %q/%v; Check has %q/%v", got.Interp, got.Static, full.Interp, full.Static)
			}
		})
	}
}

func buildFixture(t *testing.T, fx pt.Fixture) (string, string) {
	t.Helper()
	sandbox := t.TempDir()
	root, err := pt.BuildFixture(sandbox, fx)
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, root
}

func funcPtr(f phase) uintptr { return reflect.ValueOf(f).Pointer() }

// TestPhaseSelection pins the explicit phase routing: CheckShell selects
// exactly checkShell; Check selects checkShell, checkBoot, checkShortcuts in
// that order.
func TestPhaseSelection(t *testing.T) {
	ptrs := func(ps []phase) []uintptr {
		out := []uintptr{}
		for _, p := range ps {
			out = append(out, funcPtr(p))
		}
		return out
	}
	if got, want := ptrs(shellPhases()), []uintptr{funcPtr(checkShell)}; !reflect.DeepEqual(got, want) {
		t.Errorf("shellPhases = %v; want only checkShell %v", got, want)
	}
	if got, want := ptrs(allPhases()), []uintptr{funcPtr(checkShell), funcPtr(checkBoot), funcPtr(checkShortcuts)}; !reflect.DeepEqual(got, want) {
		t.Errorf("allPhases = %v; want checkShell, checkBoot, checkShortcuts %v", got, want)
	}
}

// TestRunInvokesOnlySelectedPhases: the shared admission helper calls exactly
// the phases it is given, in order, with one admitted descriptor, and none
// when the root cannot be admitted.
func TestRunInvokesOnlySelectedPhases(t *testing.T) {
	root := t.TempDir()
	var calls []string
	var fds []int
	rec := func(name string) phase {
		return func(fd int, r *Report) {
			calls = append(calls, name)
			fds = append(fds, fd)
		}
	}
	if _, err := run(root, []phase{rec("a"), rec("b")}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"a", "b"}) || len(fds) != 2 || fds[0] != fds[1] || fds[0] < 0 {
		t.Errorf("calls %v fds %v; want a, b on one admitted descriptor", calls, fds)
	}
	calls = nil
	missing := filepath.Join(root, "missing")
	_, err := run(missing, []phase{rec("x")})
	var re *RootError
	if !errors.As(err, &re) || re.Dir != missing || calls != nil {
		t.Errorf("run(missing) err %v calls %v; want RootError and no phase", err, calls)
	}
}

// TestCheckShellRootErrors: CheckShell admits the root exactly like Check.
func TestCheckShellRootErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(dir, "missing"), file} {
		_, werr := Check(p)
		_, gerr := CheckShell(p)
		var w, g *RootError
		if !errors.As(werr, &w) || !errors.As(gerr, &g) || w.Dir != g.Dir || w.Err != g.Err {
			t.Errorf("%s: CheckShell err %v; want the same RootError as Check %v", p, gerr, werr)
		}
	}
}
