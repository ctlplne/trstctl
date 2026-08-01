// SPDX-License-Identifier: MPL-2.0

// Package provenance holds the authorship and development-method record and
// the guards that keep it honest: the record cites evidence, and these tests
// fail when the cited evidence moves — the same discipline the repository
// applies to its architectural invariants (AUTHORSHIP.md §9).
package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot() string { return filepath.Join("..", "..") }

// TestAuthorshipEvidencePathsExist asserts every concrete artifact path cited
// in AUTHORSHIP.md §5 (Evidence preserved) exists in the tree. Paths that are
// [FILL] markers are facts only the owner holds and are not asserted here —
// but a cited concrete artifact that is moved or deleted fails this test, so
// the record must be updated in the same change.
func TestAuthorshipEvidencePathsExist(t *testing.T) {
	record, err := os.ReadFile("AUTHORSHIP.md")
	if err != nil {
		t.Fatalf("the authorship record itself is missing: %v", err)
	}
	text := string(record)

	// Every concrete §3/§5 citation, kept in the order the record makes them.
	evidence := []string{
		"AGENTS.md",
		"internal/crypto/AGENTS.md", // a named high-risk leaf of the hub-and-spoke contract
		"docs/design/architecture-invariants.md",
		"docs/security/threat-model.md",
		"docs/design/signing-service.md",
		"CHANGELOG.md",
		"tools/trstctllint",
		"MAINTAINERS.md",
		"NOTICE",
		"scripts/ci/license-audit.py",
		"ee/docs/claim-traceability.md",
		"internal/aimodel/zz_pii_before_test.go",
	}
	for _, rel := range evidence {
		if _, err := os.Stat(filepath.Join(repoRoot(), rel)); err != nil {
			t.Errorf("AUTHORSHIP.md cites %q as preserved evidence, but it does not exist: %v — update the record in the same change that moved it", rel, err)
		}
	}

	// The record must actually cite what this test asserts (drift the other
	// way: a reworded record silently dropping a citation).
	for _, cited := range []string{
		"`AGENTS.md`",
		"docs/design/architecture-invariants.md",
		"docs/security/threat-model.md",
		"docs/design/signing-service.md",
		"CHANGELOG.md",
		"tools/trstctllint",
		"MAINTAINERS.md",
		"ee/docs/claim-traceability.md",
		"internal/aimodel/zz_pii_before_test.go",
	} {
		if !strings.Contains(text, cited) {
			t.Errorf("AUTHORSHIP.md no longer cites %q; the record and its guard have drifted", cited)
		}
	}

	// §9 promises this very test; the promise must stay in the record.
	if !strings.Contains(text, "docs/provenance/authorship_test.go") {
		t.Error("AUTHORSHIP.md §9 no longer names its verification test")
	}
}

// TestEveryGoFileCarriesSPDXHeader is the §7 guard: every Go source file in
// the tree carries an SPDX license identifier in its head. The one historical
// straggler (internal/aimodel/zz_pii_before_test.go) was fixed in the change
// that added this guard; a new headerless file fails here.
func TestEveryGoFileCarriesSPDXHeader(t *testing.T) {
	var missing []string
	checked := 0
	err := filepath.WalkDir(repoRoot(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".sandbox-build", "dist", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		head := make([]byte, 400)
		f, err := os.Open(path) // #nosec G304 G703 -- test walks the repo's own checkout (CWE-22)
		if err != nil {
			return err
		}
		n, _ := f.Read(head)
		_ = f.Close()
		checked++
		if !strings.Contains(string(head[:n]), "SPDX-License-Identifier:") {
			rel, rerr := filepath.Rel(repoRoot(), path)
			if rerr != nil {
				rel = path
			}
			missing = append(missing, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked < 2000 {
		t.Fatalf("only %d Go files checked; the SPDX guard is not walking the tree it thinks it is", checked)
	}
	if len(missing) > 0 {
		t.Errorf("%d Go file(s) carry no SPDX-License-Identifier header: %v", len(missing), missing)
	}
}
