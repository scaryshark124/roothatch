package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"no args", nil, 0, "Usage: roothatch", ""},
		{"help", []string{"help"}, 0, "Only help and version", ""},
		{"help flag", []string{"--help"}, 0, "Usage: roothatch", ""},
		{"short help", []string{"-h"}, 0, "Usage: roothatch", ""},
		{"version", []string{"version"}, 0, "Roothatch v-test\n", ""},
		{"version flag", []string{"--version"}, 0, "Roothatch v-test\n", ""},
		{"unknown", []string{"wat"}, 2, "", "unknown command"},
		{"planned enter", []string{"enter", "/not/a/real/target"}, 2, "", "unknown command"},
		{"planned boot", []string{"boot"}, 2, "", "unknown command"},
		{"planned doctor", []string{"doctor"}, 2, "", "unknown command"},
		{"version extra", []string{"version", "oops"}, 2, "", "does not accept arguments"},
		{"help extra", []string{"help", "oops"}, 2, "", "does not accept arguments"},
		{"flag extra", []string{"--version", "oops"}, 2, "", "does not accept arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut, "v-test")
			if code != tc.code {
				t.Errorf("exit = %d; want %d", code, tc.code)
			}
			for _, stream := range []struct{ name, got, want string }{
				{"stdout", out.String(), tc.stdout}, {"stderr", errOut.String(), tc.stderr},
			} {
				if stream.want == "" && stream.got != "" {
					t.Errorf("%s = %q; want empty", stream.name, stream.got)
				}
				if stream.want != "" && !strings.Contains(stream.got, stream.want) {
					t.Errorf("%s = %q; want %q", stream.name, stream.got, stream.want)
				}
			}
			if tc.name == "version" && out.String() != "Roothatch v-test\n" {
				t.Error("version output not exact")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

func TestOutputFailureIsNotSuccess(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}} {
		var errOut bytes.Buffer
		if code := Run(args, failingWriter{}, &errOut, "v-test"); code != 1 {
			t.Errorf("exit = %d; want 1", code)
		}
		if !strings.Contains(errOut.String(), "cannot write output") {
			t.Errorf("missing output failure: %q", errOut.String())
		}
	}
}
