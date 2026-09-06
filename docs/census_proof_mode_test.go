// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---- DOCS-011: public claims name how the census actually proved each row ------
//
// tools/dodcensus/manifest.json proves every capability row one of two ways. A
// launched-binary row gate-builds cmd/trstctl and takes its HTTP response from
// that live process. An assembled-handler row drives the production
// buildRunDeps output through the assembled Server.Handler in-process; the
// census rejects any proof test that hand-constructs Deps, so the code under
// proof is production code reached through production wiring, but no binary is
// launched. Reporting that second class as "served in the shipped binary" reads
// stronger than the evidence, so this guard derives the split from the manifest
// and requires the README rows and the generated journey badges to state it.

const (
	censusModeAssembled = "assembled-handler"
	censusModeLaunched  = "launched-binary"
)

type censusProofManifest struct {
	Entries []censusProofEntry `json:"entries"`
}

type censusProofEntry struct {
	ID         string `json:"id"`
	Capability string `json:"capability"`
	Inventory  *bool  `json:"inventory"`
	Runtime    struct {
		Mode string `json:"mode"`
	} `json:"runtime"`
}

// advertisedCensusCapability mirrors advertisedInventoryCapability in
// tools/dodcensus/claims.go: the two sync backends completed by W2 stay in the
// secrets_residuals family for card reporting while counting toward the
// advertised ten-target secret-sync inventory.
func advertisedCensusCapability(entry censusProofEntry) string {
	switch entry.ID {
	case "secrets_residuals.terraform_opentofu_native_sync", "secrets_residuals.vault_kv_outbound_sync":
		return "secret_sync"
	default:
		return entry.Capability
	}
}

// servedCensusProofPhrase mirrors servedProofPhrase in tools/dodcensus/claims.go
// so the README rows the census gate writes and the rows this guard reads are
// derived from one rule.
func servedCensusProofPhrase(launched, assembled int) string {
	switch {
	case launched > 0 && assembled > 0:
		return fmt.Sprintf("served (%d by the launched shipped binary, %d through the production-assembled handler)", launched, assembled)
	case launched > 0:
		return "served by the launched shipped binary"
	case assembled > 0:
		return "served through the production-assembled handler"
	default:
		return "served"
	}
}

func loadCensusProofEntries(t *testing.T) []censusProofEntry {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash("../tools/dodcensus/manifest.json"))
	if err != nil {
		t.Fatalf("DOCS-011: read the DoD census manifest: %v", err)
	}
	var manifest censusProofManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("DOCS-011: decode the DoD census manifest: %v", err)
	}
	if len(manifest.Entries) == 0 {
		t.Fatal("DOCS-011: the DoD census manifest has no entries; revisit this guard")
	}
	return manifest.Entries
}

func TestPublicCensusClaimsStateTheProofModeSplit(t *testing.T) {
	t.Parallel()
	entries := loadCensusProofEntries(t)

	launched, assembled := 0, 0
	for _, entry := range entries {
		switch entry.Runtime.Mode {
		case censusModeLaunched:
			launched++
		case censusModeAssembled:
			assembled++
		default:
			t.Fatalf("DOCS-011: census row %s declares unknown runtime.mode %q; revisit this guard", entry.ID, entry.Runtime.Mode)
		}
	}
	total := launched + assembled
	if launched == 0 || assembled == 0 {
		t.Fatalf("DOCS-011: the census is no longer split across both proof modes (launched=%d assembled=%d); revisit this guard", launched, assembled)
	}

	launchedClaim := fmt.Sprintf("**%d of %d census rows launch the shipped binary**", launched, total)
	assembledClaim := fmt.Sprintf("**%d of %d are proved through the production-assembled handler**", assembled, total)

	readme := read(t, "../README.md")
	if strings.Contains(readme, "served in the shipped binary") {
		t.Error(`DOCS-011: README still reports rows as "served in the shipped binary"; only launched-binary census rows may claim a binary served them`)
	}
	// The proof split lives in limitations.md (maintainer vocabulary); the README
	// keeps a one-line customer summary and links there (DP2-007).
	limitations := read(t, "limitations.md")
	for _, want := range []string{launchedClaim, assembledClaim} {
		if !strings.Contains(limitations, want) {
			t.Errorf("DOCS-011: limitations.md must state the derived census proof split %q", want)
		}
		if strings.Contains(readme, want) {
			t.Errorf("DP2-007: README must not carry the census proof vocabulary %q; link limitations.md#census-proof-modes instead", want)
		}
	}
	if !strings.Contains(readme, "limitations.md#census-proof-modes") {
		t.Error("DP2-007: README must link the census proof modes section of limitations.md")
	}

	// Expressed as a slice, not a map[string]string: gosec G101 reads a map whose
	// keys include tokens like "secret" and whose values are string literals as a
	// hardcoded-credential shape. These are capability names, not credentials, and a
	// #nosec waiver for a false positive is worse than a data structure that does not
	// trip the heuristic in the first place.
	labels := []struct{ capability, label string }{
		{"connector", "Deployment connectors"},
		{"external_ca", "CA integrations"},
		{"dynamic_secret", "Dynamic-secret backends"},
		{"secret_sync", "Secret-sync targets"},
		{"hsm_kms", "HSM/KMS backends"},
	}
	type split struct{ inventory, launched, assembled int }
	perCapability := map[string]split{}
	for _, entry := range entries {
		if entry.Inventory == nil || !*entry.Inventory {
			continue
		}
		capability := advertisedCensusCapability(entry)
		current := perCapability[capability]
		current.inventory++
		if entry.Runtime.Mode == censusModeLaunched {
			current.launched++
		} else {
			current.assembled++
		}
		perCapability[capability] = current
	}
	// The slice is already in a fixed, reviewed order, so no sort is needed.
	for _, entry := range labels {
		capability := entry.capability
		got, ok := perCapability[capability]
		if !ok {
			t.Errorf("DOCS-011: the DoD manifest no longer inventories %s; revisit this guard", capability)
			continue
		}
		phrase := servedCensusProofPhrase(got.launched, got.assembled)
		// The served numerator is owned by the census gate, which rewrites it
		// from a fresh report; this guard owns only the proof-mode phrase.
		row := regexp.MustCompile(regexp.QuoteMeta(fmt.Sprintf("%s: **%d inventory / ", entry.label, got.inventory)) +
			`\d+ ` + regexp.QuoteMeta(phrase) + `\*\*`)
		if !row.MatchString(readme) {
			t.Errorf("DOCS-011: README must carry the derived row %q", fmt.Sprintf("%s: **%d inventory / <served> %s**", entry.label, got.inventory, phrase))
		}
	}

	pages, err := filepath.Glob(filepath.FromSlash("journeys/*.md"))
	if err != nil {
		t.Fatalf("DOCS-011: glob journey pages: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("DOCS-011: found no journey pages; revisit this guard")
	}
	for _, path := range pages {
		page := read(t, path)
		if strings.Contains(page, "The shipped-binary census reports") {
			t.Errorf("DOCS-011: %s still leads with the unqualified shipped-binary census claim", path)
		}
		for _, want := range []string{launchedClaim, assembledClaim} {
			if !strings.Contains(page, want) {
				t.Errorf("DOCS-011: %s badge must state the derived census proof split %q", path, want)
			}
		}
	}
}
