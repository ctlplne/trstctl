// SPDX-License-Identifier: BUSL-1.1

package ca_test

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// IssueProven must match the executable DoD census rather than a remembered list.
//
// The universal external-CA proof now starts a separate nonce-bound substrate for
// every advertised driver, drives the production assembly through its provider-
// specific wire exchange, and independently validates the issued chain. A static
// allowlist here drifted after that proof landed and left the buyer-facing matrix
// understating the evidence. Deriving this oracle from the runtime manifest makes
// either direction of drift fail: an unproved claim is rejected, and a newly
// proved authority cannot remain labeled "not tested".
func TestIssueProvenMatchesWhatIsActuallyExercised(t *testing.T) {
	t.Parallel()
	type runtimeEntry struct {
		ID          string `json:"id"`
		Enforcement string `json:"enforcement"`
		Runtime     struct {
			Test        string `json:"test"`
			Path        string `json:"path"`
			SubstrateID string `json:"substrate_id"`
		} `json:"runtime"`
	}
	var manifest struct {
		Entries []runtimeEntry `json:"entries"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "tools", "dodcensus", "manifest.json")) // #nosec G304 -- fixed in-tree proof manifest
	if err != nil {
		t.Fatalf("read DoD manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode DoD manifest: %v", err)
	}

	proved := map[string]runtimeEntry{}
	for _, entry := range manifest.Entries {
		issuer, ok := strings.CutPrefix(entry.ID, "external_ca.")
		if !ok || issuer == "registry" || issuer == "shellca" {
			continue
		}
		if entry.Enforcement != "required" || entry.Runtime.Test != "TestDODExternalCAUniversalProductionAssembly" ||
			entry.Runtime.SubstrateID != "external_ca_universal" ||
			entry.Runtime.Path != "/api/v1/external-cas/"+issuer+"/issue" {
			t.Errorf("%s does not carry the complete required universal issuance oracle: %+v", entry.ID, entry)
			continue
		}
		proved[issuer] = entry
	}

	for _, row := range ca.IssuerCapabilityMatrix() {
		entry, exercised := proved[row.Issuer]
		if row.IssueProven != exercised {
			t.Errorf("%s IssueProven=%v, but exact DoD manifest exercise=%v", row.Issuer, row.IssueProven, exercised)
		}
		if exercised && !strings.Contains(row.Evidence, entry.Runtime.Test) {
			t.Errorf("%s is exercised by %s but its evidence does not name that test: %q", row.Issuer, entry.Runtime.Test, row.Evidence)
		}
		delete(proved, row.Issuer)
	}
	if len(proved) > 0 {
		t.Errorf("DoD manifest proves external CA drivers missing from the public matrix: %v", keysOf(proved))
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

func keysOf[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
