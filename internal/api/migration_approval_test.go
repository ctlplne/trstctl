// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A migration whose members issue under an approval-required profile starts
// only with an exact, single-use approval (A40). The intent names the plan,
// the requester, the canonical request and every gated member's frozen
// issuance binding, so a different request or a changed profile revision can
// never reuse the grant.
func TestMigrationStartApprovalIntentBindsEachGatedMember(t *testing.T) {
	t.Parallel()
	gated := []migrationGatedMember{
		{IdentityID: "leaf-b", Issuance: store.OperationApprovalIssuanceBinding{ProfileName: "edge", ProfileID: "p1", ProfileVersion: 3, ProfileSpecDigest: "d3", RequestedTTLSeconds: 7200, EffectiveTTLSeconds: 3600}},
		{IdentityID: "leaf-a", Issuance: store.OperationApprovalIssuanceBinding{ProfileName: "edge", ProfileID: "p1", ProfileVersion: 3, ProfileSpecDigest: "d3", RequestedTTLSeconds: 7200, EffectiveTTLSeconds: 3600}},
	}
	intent := migrationStartApprovalIntent("tenant-a", "operator@example.test", "plan-1", "authority-1", "digest-1", gated)
	if intent.ResourceKind != "migration_run" || intent.ResourceID != "plan-1" || intent.Action != "start" ||
		intent.Requester != "operator@example.test" || intent.TenantID != "tenant-a" {
		t.Fatalf("intent = %+v; want migration_run/plan/start by the requester", intent)
	}
	again := migrationStartApprovalIntent("tenant-a", "operator@example.test", "plan-1", "authority-1", "digest-1", []migrationGatedMember{gated[1], gated[0]})
	if strings.Join(intent.EvidenceRefs, "\n") != strings.Join(again.EvidenceRefs, "\n") {
		t.Fatalf("member order changed the intent:\n%v\n%v", intent.EvidenceRefs, again.EvidenceRefs)
	}
	joined := strings.Join(intent.EvidenceRefs, "\n")
	for _, want := range []string{"migration-intent:digest-1", "authority:authority-1", "member:leaf-a", "member:leaf-b", "profile-id:p1", "profile-version:3", "profile-spec-digest:d3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence lacks %q: %v", want, intent.EvidenceRefs)
		}
	}
	changed := gated
	changed[0].Issuance.ProfileVersion = 4
	other := migrationStartApprovalIntent("tenant-a", "operator@example.test", "plan-1", "authority-1", "digest-1", changed)
	if strings.Join(other.EvidenceRefs, "\n") == joined {
		t.Fatal("a changed profile revision produced the same approval intent")
	}
}
