// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package secretscan

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CR-090. Special files never enter the reader for additive scanner rules.
func TestGitleaksCustomRulesRequiresRegularFile(t *testing.T) {
	root, err := os.MkdirTemp("", "r2-rules-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	path := filepath.Join(root, "rules.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	_, _, err = loadCustomRulesFragment(t.Context(), path, []string{root})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("custom rule plan returned %v, want a regular-file refusal", err)
	}
}
