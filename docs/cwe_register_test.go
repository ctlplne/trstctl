// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCWERegisterIsCurrent regenerates the CWE register and coverage ledger
// from the tree's #nosec waivers and fails if the committed pages differ —
// the same freshness discipline the OpenAPI golden and the claim-traceability
// table already use.
func TestCWERegisterIsCurrent(t *testing.T) {
	cmd := exec.Command("python3", "scripts/ci/gen-cwe-docs.py", "--check") // #nosec G204 -- test runs the repo's own committed generator (CWE-78)
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gen-cwe-docs.py --check failed (stale page or malformed waiver):\n%s", out)
	}
}

// TestCWEGeneratorRefusesReasonlessWaiver proves the format guard in the
// failing direction: a #nosec with no rule id or no substantive reason is a
// blanket suppression, and the generator must refuse the tree that contains
// one rather than quietly tabling it.
func TestCWEGeneratorRefusesReasonlessWaiver(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "internal", "bad")
	if err := os.MkdirAll(pkg, 0o750); err != nil {
		t.Fatal(err)
	}
	src := "package bad\n\nvar x = 1 // " + "#nosec\n"
	if err := os.WriteFile(filepath.Join(pkg, "bad.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "scripts/ci/gen-cwe-docs.py", "--root", root) // #nosec G204 -- test runs the repo's own committed generator against a tempdir fixture (CWE-78)
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("generator accepted a rule-less, reasonless #nosec:\n%s", out)
	}
	if !strings.Contains(string(out), "malformed #nosec") {
		t.Fatalf("expected a malformed-#nosec refusal, got:\n%s", out)
	}
}
