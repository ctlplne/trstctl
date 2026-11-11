// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/secretscan"
)

// Q6-L4: the on-demand scan marks a finding whose line holds a live decoy's
// value as that known decoy, at low risk, and leaves any other finding a leak.
func TestOnDemandScanMarksAKnownDecoyQ6L4(t *testing.T) {
	root := t.TempDir()
	const bait = "trstctl-bait-on-demand-7e6d5c4b" // #nosec G101 -- fabricated decoy fixture; no value is real (CWE-798)
	if err := os.WriteFile(filepath.Join(root, "app.env"), []byte("KEY="+bait+"\nOTHER=sk_fixture_value_0001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := secretscan.Report{Scanner: "gitleaks", Findings: []secretscan.Finding{
		{RuleID: "generic-api-key", File: "app.env", Line: 1, Fingerprint: "fp-bait"},
		{RuleID: "generic-api-key", File: "other.env", Line: 1, Fingerprint: "fp-other"},
	}}
	known := []secretscan.KnownValue{{ID: "d-1", Name: "lure", Value: []byte(bait)}}
	rows, _, err := discoveryFindingsFromSecretScan(report, root, known)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %d, %v", len(rows), err)
	}
	var meta struct {
		KnownDecoy *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"known_decoy"`
	}
	if err := json.Unmarshal(rows[0].Metadata, &meta); err != nil || meta.KnownDecoy == nil || meta.KnownDecoy.ID != "d-1" ||
		rows[0].RiskScore != secretscan.KnownDecoyRiskScore {
		t.Fatalf("the decoy's row: %+v %s", rows[0], rows[0].Metadata)
	}
	meta.KnownDecoy = nil
	if err := json.Unmarshal(rows[1].Metadata, &meta); err != nil || meta.KnownDecoy != nil || rows[1].RiskScore != 95 {
		t.Fatalf("the other row: %+v %s", rows[1], rows[1].Metadata)
	}
}
