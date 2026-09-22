// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"encoding/json"
	"testing"
)

func TestPQCCertificateProgressResponseCountsIssuedWithoutCallingItApplied(t *testing.T) {
	intent, log := certificateProgressFixture(t)
	p := NewProgressProjection(nil)
	applyProgressLog(t, p, log)
	response := progressResponse(intent.RunID, p.Snapshot(sealedTestTenant, intent.RunID))
	if response.Total != 1 || response.Issued != 1 || response.Applied != 0 || response.Queued != 0 || response.Failed != 0 || response.RolledBack != 0 || response.RollbackUnverified != 0 {
		t.Fatalf("issued leaf was lost or called deployed: %+v", response)
	}
	if len(response.Findings) != 1 || response.Findings[0].CertificateFingerprint != "issued-leaf-fingerprint" {
		t.Fatalf("response lost issued certificate evidence: %+v", response)
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"total", "queued", "issued", "applied", "failed", "rolled_back", "rollback_unverified", "findings"} {
		if _, ok := wire[name]; !ok {
			t.Fatalf("wire response omitted %s: %s", name, body)
		}
	}
}
