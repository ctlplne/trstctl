// SPDX-License-Identifier: BUSL-1.1

// Package provenance holds the guards for the authorship and development-method
// record. The record itself (AUTHORSHIP.md) is NOT tracked: AH-0003 unshipped it
// because it was published carrying [FILL: legal name] placeholders, and a
// provenance document with unfilled placeholders asserts less than no document at
// all. It returns only after counsel review, and the guard below is what makes
// returning in that broken state impossible.
package provenance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoRoot() string { return filepath.Join("..", "..") }

// draftMarker matches a bracketed all-caps placeholder such as [FILL: legal name]
// or [REDACTED]. Matching the shape avoids spelling debt tokens into this file.
var draftMarker = regexp.MustCompile(`\[[A-Z]{3,}[:\]]`)

// TestAuthorshipRecordShipsOnlyWhenComplete is the CODE-106 gate, and it is the
// INVERSION of the guard it replaces. The old TestAuthorshipEvidencePathsExist
// asserted the record was present and its citations resolved; it hard-failed the
// moment the record was removed, which is exactly what AH-0003 does deliberately.
//
// The real defect class is not "the record is missing" — the owner may keep it
// out of the repository for as long as counsel needs. The defect class is "the
// record ships to the public while still carrying placeholders." So this gate is
// conditional: absent is fine, present-and-complete is fine, present-and-unfilled
// fails. That lets the record come back the moment it is correct, and blocks it
// coming back the way it left.
func TestAuthorshipRecordShipsOnlyWhenComplete(t *testing.T) {
	const rel = "AUTHORSHIP.md"
	record, err := os.ReadFile(rel) // #nosec G304 -- fixed sibling path inside the package's own directory (CWE-22)
	if err != nil {
		if os.IsNotExist(err) {
			return // unshipped by AH-0003; nothing to guard until it returns
		}
		t.Fatalf("CODE-106: reading %s: %v", rel, err)
	}
	text := string(record)

	// Placeholders are the whole point of this gate. Match the SHAPE of a draft
	// marker — a bracketed all-caps token such as [FILL: legal name] — rather than
	// listing the words. Listing them would spell debt tokens into this file, which
	// CODE-101 flags and which the repository keeps at zero by invariant.
	if hits := draftMarker.FindAllString(text, -1); len(hits) > 0 {
		t.Errorf("CODE-106: %s is tracked again but still carries %d unfilled placeholder(s) %v — a provenance "+
			"record with placeholders is a draft. Fill it and have counsel review it, or keep it out of the repository.",
			rel, len(hits), hits)
	}

	// If it is back, its concrete citations must still resolve — the drift guard
	// the original test existed to provide, kept rather than discarded.
	for _, cited := range []string{
		"README.md",
		"docs/design/architecture-invariants.md",
		"docs/security/threat-model.md",
		"docs/design/signing-service.md",
		"CHANGELOG.md",
		"tools/trstctllint",
		"MAINTAINERS.md",
		"NOTICE",
		"scripts/ci/license-audit.py",
		"ee/docs/claim-traceability.md",
	} {
		if !strings.Contains(text, cited) {
			continue // the record need not cite everything it once did
		}
		if _, err := os.Stat(filepath.Join(repoRoot(), cited)); err != nil {
			t.Errorf("CODE-106: %s cites %q as preserved evidence, but it does not exist: %v — "+
				"update the record in the same change that moved it", rel, cited, err)
		}
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
		f, err := os.Open(path) // #nosec G122 G304 G703 -- test walks the repo's own checkout; no hostile symlink exposure (CWE-22, CWE-367)
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
