// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// TestAuditFindingOwnershipDocResolvesKnownDuplicates locks VERIFY-004's closure:
// duplicate audit observations must be represented as one canonical finding plus
// cross-reference-only IDs, not as multiple independent remediation tickets.
func TestAuditFindingOwnershipDocResolvesKnownDuplicates(t *testing.T) {
	body := read(t, "audit-finding-ownership.md")

	for _, want := range []string{
		"source_ids",
		"also_observed_by",
		"linked",
		"second open remediation ticket",
		"ownership exception",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit-finding-ownership.md should document %q for duplicate-root-cause handling", want)
		}
	}

	for _, row := range []struct {
		root      string
		canonical string
		crossRef  string
		owner     string
	}{
		{
			root:      "Certificate profile event sourcing and projection correctness",
			canonical: "SPINE-004",
			crossRef:  "ARCH-001",
			owner:     "SPINE",
		},
		{
			root:      "Node/Vitest browser storage runtime reproducibility",
			canonical: "TEST-004",
			crossRef:  "CODE-004",
			owner:     "TEST",
		},
	} {
		if !lineWithAll(body, row.root, row.canonical, row.crossRef, row.owner) {
			t.Errorf("audit-finding-ownership.md should map %s to canonical %s with %s as cross-reference-only", row.root, row.canonical, row.crossRef)
		}
	}
}
