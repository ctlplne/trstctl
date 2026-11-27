// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGitleaksBinaryUsesResolvedPathOutsideScanRoot(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "tools", "bin", "gitleaks")
	if err := os.MkdirAll(filepath.Dir(trusted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--report-path\" ]; then\n    shift\n    printf '[]\\n' > \"$1\"\n    break\n  fi\n  shift\ndone\n"), 0o700); err != nil { // #nosec G306 -- executable is an isolated test fixture
		t.Fatal(err)
	}
	checkout := filepath.Join(root, "checkout")
	if err := os.Mkdir(checkout, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "unexpected-scanner")
	other := filepath.Join(checkout, "tools", "bin", "gitleaks")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("#!/bin/sh\nprintf ran > "+shellQuoteForTest(marker)+"\n"), 0o700); err != nil { // #nosec G306 -- executable is an isolated test fixture
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", "")
	t.Setenv("PATH", "")
	runner := NewGitleaksRunner("")
	runner.AllowedRoots = []string{checkout}
	trusted, err := filepath.EvalSymlinks(trusted)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runner.resolveBinary()
	if err != nil || got != trusted {
		t.Fatalf("resolved binary = %q, %v; want %q", got, err, trusted)
	}
	if _, err := runner.Scan(context.Background(), checkout); err != nil {
		t.Fatalf("scan with resolved binary: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scan used a binary from the scan root: %v", err)
	}

	runner.AllowedRoots = []string{root}
	if got, err := runner.resolveBinary(); !errors.Is(err, ErrGitleaksBinaryNotFound) {
		t.Fatalf("binary inside scan root = %q, %v; want refusal", got, err)
	}
}

func TestServedGitleaksRequiresAbsoluteConfiguredBinary(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "gitleaks")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- executable is an isolated test fixture
		t.Fatal(err)
	}
	defaultBin := filepath.Join(root, "tools", "bin", "gitleaks")
	if err := os.MkdirAll(filepath.Dir(defaultBin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultBin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- executable is an isolated test fixture
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("TRSTCTL_GITLEAKS_BIN", "")
	t.Setenv("PATH", "")
	for _, configured := range []string{"", "gitleaks", filepath.Join("tools", "bin", "gitleaks")} {
		runner := NewServedGitleaksRunner(configured, nil)
		if got, err := runner.resolveBinary(); !errors.Is(err, ErrGitleaksBinaryNotFound) {
			t.Fatalf("configured %q resolved %q, %v; want absolute path requirement", configured, got, err)
		}
	}
	runner := NewServedGitleaksRunner(bin, nil)
	resolvedBin, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := runner.resolveBinary(); err != nil || got != resolvedBin {
		t.Fatalf("configured absolute binary = %q, %v; want %q", got, err, resolvedBin)
	}
}

func TestGitleaksChildEnvironmentContainsOnlyRequiredSettings(t *testing.T) {
	env := sanitizedGitleaksEnv([]string{
		"PATH=/usr/bin:/bin", "HOME=/tmp/operator", "TRSTCTL_TOKEN=private", "AWS_SECRET_ACCESS_KEY=private", "GITLEAKS_CONFIG=outside",
	})
	for _, want := range []string{"PATH=/usr/bin:/bin", "HOME=/tmp/operator", "NO_COLOR=1", "GITLEAKS_NO_UPDATE_CHECK=true"} {
		if !slices.Contains(env, want) {
			t.Fatalf("child environment %v misses %q", env, want)
		}
	}
	if len(env) != 4 {
		t.Fatalf("child environment has %d entries, want only required settings", len(env))
	}
}
