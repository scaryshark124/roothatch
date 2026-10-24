package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
			root, err := pt.BuildFixture(sandbox, fx)
			if err != nil {
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

type jsonFinding struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type jsonReport struct {
	SchemaVersion int           `json:"schema_version"`
	Result        string        `json:"result"`
	Findings      []jsonFinding `json:"findings"`
}

// checkJSONDocument verifies stdout is exactly one strict JSON report with
// exactly the documented keys, and returns it.
func checkJSONDocument(t *testing.T, stdout string) jsonReport {
	t.Helper()
	out := []byte(stdout)
	if !json.Valid(out) || !utf8.Valid(out) {
		t.Fatalf("stdout is not valid UTF-8 JSON: %q", stdout)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var r jsonReport
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("strict decode: %v\n%q", err, stdout)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatalf("second decode = %v; want io.EOF\n%q", err, stdout)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 || top["schema_version"] == nil || top["result"] == nil || top["findings"] == nil {
		t.Fatalf("top-level keys = %v; want exactly schema_version, result, findings", top)
	}
	if string(top["schema_version"]) != "1" {
		t.Errorf("schema_version = %s; want the number 1", top["schema_version"])
	}
	var fs []map[string]json.RawMessage
	if err := json.Unmarshal(top["findings"], &fs); err != nil || fs == nil {
		t.Fatalf("findings = %s (%v); want an array", top["findings"], err)
	}
	for i, f := range fs {
		if len(f) != 3 || f["code"] == nil || f["path"] == nil || f["detail"] == nil {
			t.Errorf("finding %d keys = %v; want exactly code, path, detail", i, f)
		}
	}
	if len(r.Findings) == 0 && string(bytes.TrimSpace(top["findings"])) != "[]" {
		t.Errorf("empty findings = %s; want []", top["findings"])
	}
	for _, f := range r.Findings {
		for _, s := range []string{f.Code, f.Path, f.Detail} {
			if !utf8.ValidString(s) {
				t.Errorf("decoded string not valid UTF-8: %q", s)
			}
		}
	}
	return r
}

func codeCounts(codes []string) map[string]int {
	m := map[string]int{}
	for _, c := range codes {
		m[c]++
	}
	return m
}

// TestBinaryCatalogJSON runs the compiled binary as "check --json <root>"
// against the complete catalog plus the escaping fixtures, checking the strict
// single-document schema, result, exit status, finding-code multiset, empty
// stderr and an unchanged lstat manifest of the whole sandbox.
func TestBinaryCatalogJSON(t *testing.T) {
	bin := buildBinary(t)
	catalog := pt.Catalog()
	if len(catalog) == 0 || len(pt.EscapeCatalog()) == 0 {
		t.Fatal("empty catalog")
	}
	for _, fx := range append(catalog, pt.EscapeCatalog()...) {
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
			code, stdout, stderr := runBinary(t, bin, "check", "--json", root)
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
			wantCode, wantResult := 0, "pass"
			if len(fx.Want) > 0 {
				wantCode, wantResult = 3, "findings"
			}
			if code != wantCode {
				t.Errorf("exit = %d; want %d; stdout %q", code, wantCode, stdout)
			}
			r := checkJSONDocument(t, stdout)
			if r.SchemaVersion != 1 || r.Result != wantResult {
				t.Errorf("schema_version %d result %q; want 1 %q", r.SchemaVersion, r.Result, wantResult)
			}
			var got []string
			for _, f := range r.Findings {
				got = append(got, f.Code)
			}
			if !reflect.DeepEqual(codeCounts(got), codeCounts(fx.Want)) {
				t.Errorf("finding codes = %v; want multiset %v\n%s", got, fx.Want, stdout)
			}
			if strings.Contains(stdout, root) {
				t.Errorf("output leaks host root path: %q", stdout)
			}
		})
	}
}

// sentinelState is the content and stable lstat metadata of an outside file.
type sentinelState struct {
	data  string
	mode  os.FileMode
	size  int64
	mtime time.Time
}

func readSentinel(t *testing.T, p string) sentinelState {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sentinelState{string(data), fi.Mode(), fi.Size(), fi.ModTime()}
}

// TestBinaryKernelEscape runs the compiled binary in text and --json modes on
// the escaping-kernel fixtures and their in-tree controls. After every run it
// checks the exact exit, exact ordered (code, path) findings, that JSON
// findings equal the text finding block in order, empty stderr, an unchanged
// lstat manifest of the root and unchanged outside-root sentinel files that
// the escaping links genuinely reach on the host.
func TestBinaryKernelEscape(t *testing.T) {
	runBinaryEscapeFixtures(t, "boot/vmlinuz-", "boot_kernel_escape", "boot_kernel_escape_with_valid_pair",
		"boot_two_kernel_escapes_with_valid_pair", "boot_kernel_link_in_tree", "boot_kernel_link_in_tree_relative")
}

// TestBinaryInitrdEscape applies the same real-binary checks to the
// escaping-initrd fixtures (symlink_escape then initrd_missing per version)
// and their in-tree initrd link controls.
func TestBinaryInitrdEscape(t *testing.T) {
	runBinaryEscapeFixtures(t, "boot/initrd.img-", "boot_initrd_escape", "boot_initrd_escape_with_valid_pair",
		"boot_two_initrd_escapes", "boot_initrd_link_in_tree", "boot_initrd_link_in_tree_relative")
}

// runBinaryEscapeFixtures runs the named Catalog() fixtures through the
// compiled binary; linkPrefix selects the in-root links (e.g. "boot/vmlinuz-")
// that must genuinely reach the outside sentinels on the host.
func runBinaryEscapeFixtures(t *testing.T, linkPrefix string, names ...string) {
	t.Helper()
	bin := buildBinary(t)
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	for _, name := range names {
		fx, ok := cat[name]
		if !ok {
			t.Fatalf("fixture %s not in Catalog()", name)
		}
		t.Run(name, func(t *testing.T) {
			sandbox := t.TempDir()
			root, err := pt.BuildFixture(sandbox, fx)
			if err != nil {
				t.Fatal(err)
			}
			escaping := len(fx.Want) > 0
			if escaping && len(fx.Outside) == 0 {
				t.Fatal("escaping fixture has no outside sentinel")
			}
			sentinels := map[string]sentinelState{}
			for _, e := range fx.Outside {
				p := filepath.Join(sandbox, filepath.FromSlash(e.Path))
				sentinels[p] = readSentinel(t, p)
			}
			// Each escaping link must reach a sentinel on the host, so
			// the test proves the binary refused a real outside file.
			reached := 0
			for _, e := range fx.Entries {
				// In-tree controls may use absolute targets that only resolve
				// beneath the root, so only escaping fixtures are host-checked.
				if !escaping || e.Kind != pt.KindLink || !strings.HasPrefix(e.Path, linkPrefix) {
					continue
				}
				hi, err := os.Stat(filepath.Join(root, filepath.FromSlash(e.Path)))
				if err != nil {
					t.Fatalf("host stat %s: %v", e.Path, err)
				}
				for p := range sentinels {
					if si, err := os.Stat(p); err == nil && os.SameFile(hi, si) {
						reached++
					}
				}
			}
			if escaping && reached != len(fx.Outside) {
				t.Fatalf("escaping links reach %d of %d sentinels on the host", reached, len(fx.Outside))
			}
			manifest, err := pt.Digest(root)
			if err != nil {
				t.Fatal(err)
			}
			wantCode := 0
			if escaping {
				wantCode = 3
			}
			check := func(mode string) {
				t.Helper()
				if after, err := pt.Digest(root); err != nil || after != manifest {
					t.Errorf("%s: root manifest changed (%v):\nbefore:\n%s\nafter:\n%s", mode, err, manifest, after)
				}
				for p, want := range sentinels {
					if got := readSentinel(t, p); got != want {
						t.Errorf("%s: outside sentinel %s changed: %+v; want %+v", mode, filepath.Base(p), got, want)
					}
				}
			}

			code, text, stderr := runBinary(t, bin, "check", root)
			check("text")
			if code != wantCode || stderr != "" {
				t.Errorf("text: exit %d stderr %q; want %d and empty stderr", code, stderr, wantCode)
			}
			lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
			var block []string
			for _, l := range lines {
				if strings.HasPrefix(l, "FAIL: ") || strings.HasPrefix(l, "PASS: ") ||
					strings.HasPrefix(l, "ok: ") || strings.HasPrefix(l, "note: ") {
					continue
				}
				block = append(block, l)
			}

			code, js, stderr := runBinary(t, bin, "check", "--json", root)
			check("json")
			if code != wantCode || stderr != "" {
				t.Errorf("json: exit %d stderr %q; want %d and empty stderr", code, stderr, wantCode)
			}
			r := checkJSONDocument(t, js)
			gotP := []pt.FindingPair{}
			rendered := []string{}
			for _, f := range r.Findings {
				gotP = append(gotP, pt.FindingPair{Code: f.Code, Path: f.Path})
				rendered = append(rendered, f.Code+": "+f.Path+": "+f.Detail)
			}
			wantP := append([]pt.FindingPair{}, fx.Findings...)
			if !reflect.DeepEqual(gotP, wantP) {
				t.Errorf("json (code, path) = %v; want %v\n%s", gotP, wantP, js)
			}
			if !reflect.DeepEqual(append([]string{}, block...), rendered) {
				t.Errorf("text finding block = %q; want JSON findings in order %q", block, rendered)
			}
			if escaping && (!strings.HasPrefix(lines[len(lines)-1], "FAIL: ") || r.Result != "findings") {
				t.Errorf("verdict text %q json %q; want FAIL and findings", lines[len(lines)-1], r.Result)
			}
			if !escaping && (!strings.HasPrefix(lines[len(lines)-1], "PASS: ") || r.Result != "pass") {
				t.Errorf("verdict text %q json %q; want PASS and pass", lines[len(lines)-1], r.Result)
			}
			for _, out := range []string{text, js} {
				if strings.Contains(out, "must never be read") {
					t.Errorf("sentinel content leaked: %q", out)
				}
			}
		})
	}
}

// TestBinaryJSONUsage covers rejected --json argument forms and unusable
// directories: exit 2, empty stdout, explanation on stderr.
func TestBinaryJSONUsage(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", dir, "--json"},
		{"check", "--json"},
		{"check", "--json", dir, dir},
		{"check", "--json", "--json", dir},
		{"check", "--JSON", dir},
		{"check", "-json", dir},
		{"check", "--json=true", dir},
		{"check", "--json", filepath.Join(dir, "missing")},
		{"check", "--json", file},
	} {
		code, stdout, stderr := runBinary(t, bin, args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q; want 2, empty stdout, nonempty stderr", args, code, stdout, stderr)
		}
	}
}

// TestBinaryJSONOutputFailure writes JSON to /dev/full: an output failure
// must exit 1 for both a passing and a findings fixture.
func TestBinaryJSONOutputFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); errors.Is(err, os.ErrNotExist) {
		t.Skip("/dev/full is absent")
	}
	bin := buildBinary(t)
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	for _, name := range []string{"healthy_merged_usr", "missing_shell"} {
		root := filepath.Join(t.TempDir(), "root")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := pt.Build(root, cat[name].Entries...); err != nil {
			t.Fatal(err)
		}
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, bin, "check", "--json", root)
		cmd.Stdout, cmd.Stderr = full, &stderr
		cmd.Env = []string{"LC_ALL=C"}
		err = cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		full.Close()
		if timedOut {
			t.Fatalf("%s: binary did not finish within 20s", name)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Errorf("%s: run error %v; want exit 1 (stderr %q)", name, err, stderr.String())
		}
	}
}

// runBothModes runs the compiled binary on root in text and --json modes and
// checks the exact exit, empty stderr, exact ordered (code, path) pairs, that
// the text finding block equals the JSON findings in order, and the verdict.
// It returns the JSON findings.
func runBothModes(t *testing.T, bin, root string, want []pt.FindingPair) []jsonFinding {
	t.Helper()
	wantCode, wantVerdict, wantResult := 0, "PASS: ", "pass"
	if len(want) > 0 {
		wantCode, wantVerdict, wantResult = 3, "FAIL: ", "findings"
	}
	code, text, stderr := runBinary(t, bin, "check", root)
	if code != wantCode || stderr != "" {
		t.Errorf("text: exit %d stderr %q; want %d and empty stderr", code, stderr, wantCode)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	var block []string
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL: ") || strings.HasPrefix(l, "PASS: ") ||
			strings.HasPrefix(l, "ok: ") || strings.HasPrefix(l, "note: ") {
			continue
		}
		block = append(block, l)
	}
	code, js, stderr := runBinary(t, bin, "check", "--json", root)
	if code != wantCode || stderr != "" {
		t.Errorf("json: exit %d stderr %q; want %d and empty stderr", code, stderr, wantCode)
	}
	r := checkJSONDocument(t, js)
	gotP := []pt.FindingPair{}
	rendered := []string{}
	for _, f := range r.Findings {
		gotP = append(gotP, pt.FindingPair{Code: f.Code, Path: f.Path})
		rendered = append(rendered, f.Code+": "+f.Path+": "+f.Detail)
	}
	if !reflect.DeepEqual(gotP, append([]pt.FindingPair{}, want...)) {
		t.Errorf("json (code, path) = %v; want %v\n%s", gotP, want, js)
	}
	if !reflect.DeepEqual(append([]string{}, block...), rendered) {
		t.Errorf("text finding block = %q; want JSON findings in order %q", block, rendered)
	}
	if !strings.HasPrefix(lines[len(lines)-1], wantVerdict) || r.Result != wantResult {
		t.Errorf("verdict text %q json %q; want %q and %q", lines[len(lines)-1], r.Result, wantVerdict, wantResult)
	}
	if strings.Contains(text+js, root) {
		t.Errorf("output leaks host root path")
	}
	return r.Findings
}

// TestBinaryInterpHeader runs the compiled binary in text and --json modes on
// every interpreter header fixture plus the static-shell control, checking
// exact ordered findings, exit, stderr and an unchanged whole-sandbox manifest.
func TestBinaryInterpHeader(t *testing.T) {
	bin := buildBinary(t)
	fxs := pt.InterpCatalog()
	for _, fx := range pt.Catalog() {
		if fx.Name == "static_shell" {
			fxs = append(fxs, fx)
		}
	}
	if len(fxs) != 14 {
		t.Fatalf("got %d fixtures; want 13 interpreter fixtures plus static_shell", len(fxs))
	}
	for _, fx := range fxs {
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
			got := runBothModes(t, bin, root, fx.Findings)
			for _, f := range got {
				if !strings.Contains(f.Detail, "header-level check") || !strings.Contains(f.Detail, "not a verdict that the loader works") {
					t.Errorf("detail lacks header-level disclaimer: %q", f.Detail)
				}
			}
			if after, err := pt.Digest(sandbox); err != nil || after != before {
				t.Errorf("manifest changed (%v):\nbefore:\n%s\nafter:\n%s", err, before, after)
			}
		})
	}
}

// TestBinaryInterpUnreadable makes the regular interpreter unreadable: both
// modes report exactly read_error at the PT_INTERP path and leave the sandbox
// (including the loader's lstat metadata) unchanged.
func TestBinaryInterpUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not deny root")
	}
	bin := buildBinary(t)
	var fx pt.Fixture
	for _, f := range pt.Catalog() {
		if f.Name == "healthy_merged_usr" {
			fx = f
		}
	}
	sandbox := t.TempDir()
	root, err := pt.BuildFixture(sandbox, fx)
	if err != nil {
		t.Fatal(err)
	}
	ld := filepath.Join(root, "usr/lib64/ld-linux-x86-64.so.2")
	before, err := pt.Digest(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ld, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ld, 0o755) })
	pre, err := os.Lstat(ld)
	if err != nil {
		t.Fatal(err)
	}
	got := runBothModes(t, bin, root, []pt.FindingPair{{Code: "read_error", Path: pt.Loader}})
	if len(got) == 1 && !strings.HasPrefix(got[0].Detail, "cannot read: ") {
		t.Errorf("detail = %q; want \"cannot read: \" prefix", got[0].Detail)
	}
	post, err := os.Lstat(ld)
	if err != nil || post.Mode() != pre.Mode() || post.Size() != pre.Size() || !post.ModTime().Equal(pre.ModTime()) {
		t.Errorf("loader metadata changed: %v (%v); want %v", post, err, pre)
	}
	if err := os.Chmod(ld, 0o755); err != nil {
		t.Fatal(err)
	}
	if after, err := pt.Digest(sandbox); err != nil || after != before {
		t.Errorf("manifest changed (%v):\nbefore:\n%s\nafter:\n%s", err, before, after)
	}
}
