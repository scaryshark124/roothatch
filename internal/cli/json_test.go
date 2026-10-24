package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/scaryshark124/roothatch/internal/preflight"
	pt "github.com/scaryshark124/roothatch/internal/preflight/preflighttest"
)

type strictFinding struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type strictReport struct {
	SchemaVersion int             `json:"schema_version"`
	Result        string          `json:"result"`
	Findings      []strictFinding `json:"findings"`
}

// decodeStrict decodes exactly one strict JSON report from out and requires
// exactly the documented keys.
func decodeStrict(t *testing.T, out []byte) strictReport {
	t.Helper()
	if !json.Valid(out) {
		t.Fatalf("stdout is not valid JSON: %q", out)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var r strictReport
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("strict decode: %v\n%q", err, out)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatalf("second decode = %v; want io.EOF\n%q", err, out)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 || top["schema_version"] == nil || top["result"] == nil || top["findings"] == nil {
		t.Fatalf("top-level keys = %v; want schema_version, result, findings", top)
	}
	if string(top["schema_version"]) != "1" {
		t.Errorf("schema_version = %s; want number 1", top["schema_version"])
	}
	var fs []map[string]json.RawMessage
	if err := json.Unmarshal(top["findings"], &fs); err != nil || fs == nil {
		t.Fatalf("findings = %s (%v); want array", top["findings"], err)
	}
	for i, f := range fs {
		if len(f) != 3 || f["code"] == nil || f["path"] == nil || f["detail"] == nil {
			t.Errorf("finding %d keys = %v; want code, path, detail", i, f)
		}
	}
	return r
}

// TestCheckJSONMatchesReport proves --json serializes exactly the report of
// preflight.Check: same findings, order, multiplicity and sanitized strings.
func TestCheckJSONMatchesReport(t *testing.T) {
	for _, fx := range append(pt.Catalog(), pt.EscapeCatalog()...) {
		t.Run(fx.Name, func(t *testing.T) {
			sandbox, root := fixtureRoot(t, fx)
			want, err := preflight.Check(root)
			if err != nil {
				t.Fatal(err)
			}
			before, err := pt.Digest(sandbox)
			if err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run([]string{"check", "--json", root}, &out, &errOut, "v")
			if after, err := pt.Digest(sandbox); err != nil || after != before {
				t.Errorf("fixture changed (%v)", err)
			}
			if errOut.Len() != 0 {
				t.Errorf("stderr = %q; want empty", errOut.String())
			}
			wantCode, wantResult := 0, "pass"
			if len(fx.Want) > 0 {
				wantCode, wantResult = 3, "findings"
			}
			if code != wantCode {
				t.Fatalf("exit = %d; want %d; stdout %q", code, wantCode, out.String())
			}
			got := decodeStrict(t, out.Bytes())
			if got.Result != wantResult || got.SchemaVersion != 1 {
				t.Errorf("result %q schema %d; want %q 1", got.Result, got.SchemaVersion, wantResult)
			}
			wantF := []strictFinding{}
			for _, f := range want.Findings {
				wantF = append(wantF, strictFinding{f.Code, f.Path, f.Detail})
			}
			if !reflect.DeepEqual(got.Findings, wantF) {
				t.Errorf("findings = %#v; want %#v", got.Findings, wantF)
			}
			if fx.Findings != nil {
				gotP := []pt.FindingPair{}
				for _, f := range got.Findings {
					gotP = append(gotP, pt.FindingPair{Code: f.Code, Path: f.Path})
				}
				if !reflect.DeepEqual(gotP, fx.Findings) {
					t.Errorf("JSON (code, path) = %v; want %v", gotP, fx.Findings)
				}
			}
			for _, f := range got.Findings {
				for _, s := range []string{f.Code, f.Path, f.Detail} {
					if !utf8.ValidString(s) {
						t.Errorf("decoded string not UTF-8: %q", s)
					}
				}
			}
		})
	}
}

func TestCheckJSONUsage(t *testing.T) {
	root := newRoot(t, pt.Catalog()[0].Entries...)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", root, "--json"},
		{"check", "--json"},
		{"check", "--json", root, root},
		{"check", "--json", "--json", root},
		{"check", "--JSON", root},
		{"check", "-json", root},
		{"check", "--json=true", root},
		{"check", "--json", "/nonexistent-roothatch-test-dir"},
		{"check", "--json", file},
	} {
		var out, errOut bytes.Buffer
		if code := Run(args, &out, &errOut, "v"); code != 2 {
			t.Errorf("%q: exit = %d; want 2", args, code)
		}
		if out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("%q: stdout %q stderr %q; want empty stdout, nonempty stderr", args, out.String(), errOut.String())
		}
	}
}

func TestHelpDocumentsJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"help"}, &out, &errOut, "v"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, s := range []string{"roothatch check --json <dir>", `"pass"`, "not a bootability verdict"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("help lacks %q:\n%s", s, out.String())
		}
	}
}

func TestCheckJSONOutputFailure(t *testing.T) {
	cat := map[string]pt.Fixture{}
	for _, fx := range pt.Catalog() {
		cat[fx.Name] = fx
	}
	for _, name := range []string{"healthy_merged_usr", "missing_shell"} {
		root := newRoot(t, cat[name].Entries...)
		var errOut bytes.Buffer
		if code := Run([]string{"check", "--json", root}, failingWriter{}, &errOut, "v"); code != 1 {
			t.Errorf("%s: exit = %d; want 1", name, code)
		}
		if !strings.Contains(errOut.String(), "cannot write output") {
			t.Errorf("%s: stderr = %q", name, errOut.String())
		}
	}
}
