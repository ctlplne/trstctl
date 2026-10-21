// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// A PQC certificate migration under an approval-required profile starts only
// with an exact single-use approval bound to the canonical request and every
// gated reissue's frozen issuance binding (A40).
func TestPQCMigrationApprovalIntentBindsGatedReissues(t *testing.T) {
	t.Parallel()
	req := APIRequest{AssetIDs: []string{"asset-b", "asset-a"}, TargetAlgorithm: "ML-DSA-65", Protocol: "host-csr",
		CertificateBindings: []APICertificateBinding{{AssetID: "asset-a", IdentityID: "id-a", TargetID: "t-a"}, {AssetID: "asset-b", IdentityID: "id-b", TargetID: "t-b"}}}
	gated := map[string]certificateExecutionBinding{
		"asset-b": {Identity: store.Identity{ID: "id-b"}, RequiresApproval: true, Issuance: store.OperationApprovalIssuanceBinding{ProfileName: "pqc", ProfileID: "p", ProfileVersion: 2, ProfileSpecDigest: "d", RequestedTTLSeconds: 100, EffectiveTTLSeconds: 100}},
		"asset-a": {Identity: store.Identity{ID: "id-a"}, RequiresApproval: false},
	}
	intent, err := pqcMigrationApprovalIntent("tenant-a", "operator@example.test", req, gated)
	if err != nil {
		t.Fatal(err)
	}
	if intent.ResourceKind != "pqc_migration_run" || intent.Action != "start" || intent.Requester != "operator@example.test" || intent.ResourceID == "" {
		t.Fatalf("intent = %+v", intent)
	}
	joined := strings.Join(intent.EvidenceRefs, "\n")
	for _, want := range []string{"asset:asset-b", "identity:id-b", "profile-id:p", "profile-version:2", "target-algorithm:ML-DSA-65"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence lacks %q: %v", want, intent.EvidenceRefs)
		}
	}
	if strings.Contains(joined, "asset:asset-a") {
		t.Errorf("an ungated reissue was bound into the approval: %v", intent.EvidenceRefs)
	}
	reordered := req
	reordered.AssetIDs = []string{"asset-a", "asset-b"}
	again, err := pqcMigrationApprovalIntent("tenant-a", "operator@example.test", reordered, gated)
	if err != nil || again.ResourceID != intent.ResourceID {
		t.Fatalf("asset order changed the request identity: %s vs %s (%v)", again.ResourceID, intent.ResourceID, err)
	}

	now := time.Now()
	for name, tc := range map[string]struct {
		request store.OperationApprovalRequest
		ready   bool
	}{
		"approved": {store.OperationApprovalRequest{Status: store.ApprovalStatusApproved, ApprovalCount: 2, RequiredApprovals: 2, ExpiresAt: now.Add(time.Hour)}, true},
		"pending":  {store.OperationApprovalRequest{Status: store.ApprovalStatusPending, RequiredApprovals: 2, ExpiresAt: now.Add(time.Hour)}, false},
		"expired":  {store.OperationApprovalRequest{Status: store.ApprovalStatusApproved, ApprovalCount: 2, RequiredApprovals: 2, ExpiresAt: now.Add(-time.Hour)}, false},
	} {
		if got := pqcMigrationApprovalReady(tc.request, now); got != tc.ready {
			t.Errorf("%s: ready = %v, want %v", name, got, tc.ready)
		}
	}
}
