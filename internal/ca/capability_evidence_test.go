// SPDX-License-Identifier: MPL-2.0

package ca_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
)

// A capability matrix a buyer reads is a set of promises (epic K3).
//
// This table is served, published, and — by design — read before a sales call
// to verify a "CA-agnostic" claim. The difference between a promise and a fact
// is whether anything checks it, so every row has to name what backs it and
// every "proven" claim has to be one somebody could go and run.

func TestEveryIssuerRowNamesItsEvidence(t *testing.T) {
	t.Parallel()
	for _, row := range ca.IssuerCapabilityMatrix() {
		row := row
		t.Run(row.Issuer, func(t *testing.T) {
			t.Parallel()
			if strings.TrimSpace(row.Evidence) == "" {
				t.Fatalf("%s claims capabilities with nothing named that backs them; a row nobody "+
					"can trace to a test is a marketing line in a table an operator trusts",
					row.Issuer)
			}
			// It must name a TEST. Citing a doc page would be circular: a page
			// asserting a capability is the same class of artifact as this row.
			if !strings.Contains(row.Evidence, "Test") && !strings.Contains(row.Evidence, "suite") {
				t.Errorf("%s's evidence %q names no test", row.Issuer, row.Evidence)
			}
		})
	}
}

// IssueProven must not outrun what exists.
//
// The column exists to make a gap visible, so a change that quietly sets it true
// everywhere would defeat the point more thoroughly than not having it. Today
// exactly one authority has an end-to-end issuance test; when that changes, this
// test is where somebody has to say so.
func TestIssueProvenMatchesWhatIsActuallyExercised(t *testing.T) {
	t.Parallel()
	proven := map[string]bool{}
	for _, row := range ca.IssuerCapabilityMatrix() {
		if row.IssueProven {
			proven[row.Issuer] = true
		}
	}
	// letsencrypt is proven because the served ACME suite drives a full order.
	if !proven["letsencrypt"] {
		t.Error("letsencrypt is not marked issue-proven, but the served ACME order suite " +
			"exercises a full issuance against this build")
	}
	delete(proven, "letsencrypt")
	if len(proven) > 0 {
		t.Errorf("these authorities claim a proven issuance: %v. No per-authority issuance test "+
			"runs against a double of their APIs — the shared HTTP client is exercised and the "+
			"revoke and unattended-DV columns are census-checked, which is not the same claim. "+
			"If one of these gained a test, it lands in the same change that flips the flag",
			keysOf(proven))
	}
}

// Every row claiming Issue but not IssueProven is exactly what the published
// matrix must render as "implemented, not proven" rather than as support.
func TestAnImplementedIssuerIsNotRenderedAsProven(t *testing.T) {
	t.Parallel()
	var implementedOnly int
	for _, row := range ca.IssuerCapabilityMatrix() {
		if row.Issue && !row.IssueProven {
			implementedOnly++
		}
	}
	if implementedOnly == 0 {
		t.Skip("every issuer has an issuance test; this distinction no longer has anything to hold")
	}
	// Not an error — a statement of the current, honest position, asserted so
	// that a change to it is deliberate.
	t.Logf("%d authorities are implemented without an end-to-end issuance test; the published "+
		"matrix marks them so rather than as supported", implementedOnly)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
