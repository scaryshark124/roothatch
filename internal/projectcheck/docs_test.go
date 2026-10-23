package projectcheck

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func root(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRequiredDocuments(t *testing.T) {
	for _, name := range []string{
		"README.md", "MASTER_CHECKLIST.md", "CONTRIBUTING.md", "SECURITY.md", "AGENTS.md", "LICENSE", "NOTICE",
		"docs/PRODUCT_BRIEF.md", "docs/ARCHITECTURE.md", "docs/decisions/README.md",
		"docs/development/CURRENT_STATE.md", "docs/development/DELIVERY_POLICY.md",
		"docs/development/TASK_TEMPLATE.md", "docs/development/VERIFICATION.md",
		"docs/development/KANBAN.md",
	} {
		data, err := os.ReadFile(filepath.Join(root(t), name))
		if err != nil || len(data) == 0 {
			t.Errorf("required document %s empty or unreadable: %v", name, err)
		}
	}
}

func TestLicenseAndModuleIdentity(t *testing.T) {
	r := root(t)
	license, err := os.ReadFile(filepath.Join(r, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	// Exact canonical Apache text, verified against apache.org at adoption.
	const wantLicense = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
	if got := fmt.Sprintf("%x", sha256.Sum256(license)); got != wantLicense {
		t.Errorf("LICENSE digest = %s; want canonical Apache-2.0", got)
	}
	for name, marker := range map[string]string{
		"go.mod":                "module github.com/scaryshark124/roothatch\n",
		"cmd/roothatch/main.go": "\"github.com/scaryshark124/roothatch/internal/cli\"",
		"NOTICE":                "Copyright 2026 The Roothatch Authors",
		"README.md":             "Apache License, Version 2.0 (Apache-2.0)",
		"AGENTS.md":             "TASK_SCOPE_CHECK: PASS",
	} {
		data, err := os.ReadFile(filepath.Join(r, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), marker) {
			t.Errorf("%s missing selected identity %q", name, marker)
		}
	}
}

func TestChecklistIDsAreUnique(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root(t), "MASTER_CHECKLIST.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := regexp.MustCompile(`(?m)^- \[[ x]\] \*\*(RH-[A-Z0-9]+-[0-9]+)\*\*`).FindAllStringSubmatch(string(data), -1)
	if len(ids) < 30 {
		t.Fatalf("expected complete capability inventory, got %d IDs", len(ids))
	}
	seen := make(map[string]bool)
	for _, m := range ids {
		if seen[m[1]] {
			t.Errorf("duplicate requirement %s", m[1])
		}
		seen[m[1]] = true
	}
	for _, id := range []string{"RH-M3-01", "RH-M4-02", "RH-M5-04", "RH-M6-01"} {
		if !seen[id] {
			t.Errorf("missing build/boot/rehearsal/release requirement %s", id)
		}
	}
}

func TestLocalMarkdownLinksResolve(t *testing.T) {
	r := root(t)
	links := regexp.MustCompile(`\[[^\]\n]+\]\(([^\s)]+)\)`)
	err := filepath.WalkDir(r, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "bin") {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range links.FindAllStringSubmatch(string(data), -1) {
			ref := strings.SplitN(m[1], "#", 2)[0]
			if ref == "" || strings.Contains(ref, "://") || strings.HasPrefix(ref, "mailto:") {
				continue
			}
			if filepath.IsAbs(ref) {
				t.Errorf("nonportable absolute link in %s: %s", path, ref)
				continue
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), ref)); err != nil {
				t.Errorf("broken link in %s: %s", path, ref)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScopeAndRolesRemainExplicit(t *testing.T) {
	checks := map[string][]string{
		"README.md":                           {"Only `help` and `version`", "Apache-2.0", "Native entry and VM boot"},
		"docs/development/DELIVERY_POLICY.md": {"ironcladexec", "ironcladreview", "ironcladsecurity", "TASK_SCOPE_CHECK: PASS", "Functional", "defensive"},
		"docs/PRODUCT_BRIEF.md":               {"debootstrap", "real VM boot", "Swap", "concurrently"},
	}
	for name, tokens := range checks {
		data, err := os.ReadFile(filepath.Join(root(t), name))
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range tokens {
			if !strings.Contains(string(data), token) {
				t.Errorf("%s missing scope marker %q", name, token)
			}
		}
	}
}
