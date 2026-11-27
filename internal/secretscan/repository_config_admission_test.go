// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPlanConfinesRepositoryConfigInputs(t *testing.T) {
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.toml")
	if err := os.WriteFile(outside, []byte("[[rules]]\nid = 'outside'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := fakeGitleaksCommand(t, filepath.Join(t.TempDir(), "args"), filepath.Join(t.TempDir(), "config"), `[]`)
	runner := NewGitleaksRunner(binary)
	runner.AllowedRoots = []string{repo}
	for name, data := range map[string][]byte{
		"nested path":      []byte("[extend]\npath = '" + outside + "'\n"),
		"quoted table":     []byte("[\"extend\"]\npath = '" + outside + "'\n"),
		"dotted extension": []byte("extend.path = '" + outside + "'\n"),
		"large file":       bytes.Repeat([]byte("#"), 1<<20+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runner.PlanContext(context.Background(), repo, ScanOptions{}); !errors.Is(err, ErrInvalidCustomRules) {
				t.Fatalf("repository config admission = %v, want invalid rules", err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), []byte("[extend]\npath = '"+outside+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.ScanWithOptions(context.Background(), repo, ScanOptions{}); !errors.Is(err, ErrInvalidCustomRules) {
		t.Fatalf("scan config admission = %v, want invalid rules", err)
	}
}

func TestScanConfigUsesBoundedRepositorySnapshot(t *testing.T) {
	repo := t.TempDir()
	content := []byte("[extend]\nuseDefault = true\n\n[[rules]]\nid = 'sample'\n")
	if err := os.WriteFile(filepath.Join(repo, ".gitleaks.toml"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := prepareCustomRulesConfig(context.Background(), "", []string{repo}, repo)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	generated, err := os.ReadFile(path) // #nosec G304 -- reads the config created by this test
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(generated), filepath.Join(repo, ".gitleaks.toml")) {
		t.Fatal("scanner config referred to a mutable repository file")
	}
	var snapshot string
	for _, line := range strings.Split(string(generated), "\n") {
		if strings.HasPrefix(line, "path = ") {
			snapshot = strings.Trim(strings.TrimPrefix(line, "path = "), `\"'`)
			break
		}
	}
	if snapshot == "" {
		t.Fatal("scanner config has no repository snapshot")
	}
	got, err := os.ReadFile(snapshot) // #nosec G304,G703 -- reads the snapshot created by this test
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("snapshot = %q, %v; want admitted config", got, err)
	}
	cleanup()
	for _, removed := range []string{path, snapshot} {
		if _, err := os.Stat(removed); !errors.Is(err, os.ErrNotExist) { // #nosec G703 -- checks the test-owned temporary files
			t.Fatalf("temporary scanner config still exists: %q, %v", removed, err)
		}
	}
}
