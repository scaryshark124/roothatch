package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

// buildBinary compiles the real roothatch command into a temporary directory.
// os/exec is used only by this test; production code stays exec-free.
func buildBinary(t *testing.T) string {
	t.Helper()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goTool); err != nil {
		if goTool, err = exec.LookPath("go"); err != nil {
			t.Skip("go tool not available to build the binary")
		}
	}
	bin := filepath.Join(t.TempDir(), "roothatch")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// runBinary executes the built command with a per-run timeout.
func runBinary(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Env = []string{"LC_ALL=C"}
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("binary did not finish within 20s: %v", ctx.Err())
	}
	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("cannot run binary: %v", err)
	}
	return code, stdout.String(), stderr.String()
}

// TestBinaryCatalog runs the compiled binary against every catalog fixture and
// checks exit status, exact finding codes, verdict line, empty stderr and an
// lstat manifest (path, mode, sha256, link target; links never followed) of
// the whole sandbox, including outside-root areas, before and after each run.
func TestBinaryCatalog(t *testing.T) {
	bin := buildBinary(t)
	catalog := pt.Catalog()
	if len(catalog) == 0 {
		t.Fatal("empty catalog")
	}
	for _, fx := range catalog {
		t.Run(fx.Name, func(t *testing.T) {
			sandbox := t.TempDir()
			root := filepath.Join(sandbox, "root")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := pt.Build(root, fx.Entries...); err != nil {
				t.Fatal(err)
			}
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runBinary(t, bin, "check", root)
			after, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("manifest changed:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if stderr != "" {
				t.Errorf("stderr = %q; want empty", stderr)
			}
			lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
			last := lines[len(lines)-1]
			got := []string{}
			for _, l := range lines {
				if c, _, ok := strings.Cut(l, ": "); ok && c != "ok" && c != "note" && c != "PASS" && c != "FAIL" {
					got = append(got, c)
				}
			}
			want := append([]string{}, fx.Want...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("finding codes = %v; want %v\n%s", got, want, stdout)
			}
			if len(want) == 0 {
				if code != 0 || !strings.HasPrefix(last, "PASS: limited checks passed") || strings.Contains(stdout, "FAIL:") {
					t.Errorf("exit %d, stdout %q; want 0 and PASS", code, stdout)
				}
				if !strings.Contains(last, "does not show the root is bootable or healthy") {
					t.Errorf("PASS line lacks disclaimer: %q", last)
				}
				for _, k := range fx.Kernels {
					if !strings.Contains(stdout, k) {
						t.Errorf("PASS output lacks kernel %q: %q", k, stdout)
					}
				}
				return
			}
			if code != 3 || !strings.HasPrefix(last, "FAIL: ") || strings.Contains(stdout, "PASS:") {
				t.Errorf("exit %d, stdout %q; want 3 and FAIL", code, stdout)
			}
			if strings.Contains(stdout, root) {
				t.Errorf("output leaks host root path: %q", stdout)
			}
		})
	}
}

// TestBinaryUsage covers the unchanged usage exit code of the real binary.
func TestBinaryUsage(t *testing.T) {
	bin := buildBinary(t)
	if code, stdout, stderr := runBinary(t, bin, "check"); code != 2 || stdout != "" || stderr == "" {
		t.Errorf("check without dir: exit %d stdout %q stderr %q; want 2", code, stdout, stderr)
	}
}
