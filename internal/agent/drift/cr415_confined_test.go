// SPDX-License-Identifier: BUSL-1.1

package drift_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/drift"
)

func TestCR415ConfinedDriftAllowsOnlyOperatorRootAndRechecksSymlinks(t *testing.T) {
	parent := t.TempDir()
	approved := filepath.Join(parent, "approved")
	outside := filepath.Join(parent, "outside")
	for _, dir := range []string{approved, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := drift.ApprovedRoots([]string{approved})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(approved, "leaf.pem")
	if err := os.WriteFile(path, []byte("drifted"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := drift.Watched{Path: path, Class: "certificate", Fingerprint: drift.Fingerprint([]byte("declared"))}
	findings, err := drift.DetectConfined(context.Background(), roots, []drift.Watched{w})
	if err != nil || len(findings) != 1 || findings[0].Type != drift.Replaced {
		t.Fatalf("approved file = %+v, %v; want one replaced finding", findings, err)
	}
	alias := filepath.Join(approved, "alias.pem")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := drift.ValidateConfinedPaths(roots, []drift.Watched{w, {Path: alias, Class: w.Class, Fingerprint: w.Fingerprint}}, nil); err == nil {
		t.Fatal("two watched paths naming the same file were accepted")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("declared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, path); err != nil {
		t.Fatal(err)
	}
	if _, err := drift.DetectConfined(context.Background(), roots, []drift.Watched{w}); !errors.Is(err, drift.ErrPathNotApproved) {
		t.Fatalf("swapped symlink read = %v, want confinement refusal", err)
	}
	if err := os.Remove(canary); err != nil {
		t.Fatal(err)
	}
	if err := drift.ValidateConfinedPaths(roots, []drift.Watched{w}, nil); !errors.Is(err, drift.ErrPathNotApproved) {
		t.Fatalf("dangling outside symlink admission = %v, want refusal", err)
	}
	w.Path = canary
	if err := drift.ValidateConfinedPaths(roots, []drift.Watched{w}, nil); !errors.Is(err, drift.ErrPathNotApproved) {
		t.Fatalf("direct outside path admission = %v, want refusal", err)
	}
}

func TestCR415ConfinedDriftRejectsKernelAndUnboundedPlans(t *testing.T) {
	root := t.TempDir()
	roots, err := drift.ApprovedRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "leaf.pem")
	w := drift.Watched{Path: base, Class: "certificate", Fingerprint: "digest"}
	if err := drift.ValidateConfinedPaths(roots, []drift.Watched{w, w}, nil); err == nil {
		t.Fatal("duplicate watched path was accepted")
	}
	if err := drift.ValidateConfinedPaths([]string{"/proc"}, []drift.Watched{{Path: "/proc/self/cmdline", Class: "certificate", Fingerprint: "digest"}}, nil); err == nil {
		t.Fatal("kernel pseudo-file was accepted")
	}
}
