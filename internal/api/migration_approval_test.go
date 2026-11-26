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
		{IdentityID: "leaf-b", IssuingAuthorityID: "ca-1", IssuingAuthoritySource: "internal", TargetID: "target-b", TargetRevision: "rev-7", PredecessorCertificateID: "cert-b", PredecessorFingerprint: "fingerprint-b", Issuance: store.OperationApprovalIssuanceBinding{ProfileName: "edge", ProfileID: "p1", ProfileVersion: 3, ProfileSpecDigest: "d3", RequestedTTLSeconds: 7200, EffectiveTTLSeconds: 3600}},
		{IdentityID: "leaf-a", IssuingAuthorityID: "ca-1", IssuingAuthoritySource: "internal", TargetID: "target-a", TargetRevision: "rev-7", PredecessorCertificateID: "cert-a", PredecessorFingerprint: "fingerprint-a", Issuance: store.OperationApprovalIssuanceBinding{ProfileName: "edge", ProfileID: "p1", ProfileVersion: 3, ProfileSpecDigest: "d3", RequestedTTLSeconds: 7200, EffectiveTTLSeconds: 3600}},
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
	for _, want := range []string{"migration-intent:digest-1", "authority:authority-1", "member:leaf-a", "member:leaf-b", "profile-id:p1", "profile-version:3", "profile-spec-digest:d3", "issuer:internal/ca-1", "target:target-a", "revision:rev-7", "predecessor:cert-a/fingerprint-a"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence lacks %q: %v", want, intent.EvidenceRefs)
		}
	}
	changed := append([]migrationGatedMember(nil), gated...)
	changed[0].Issuance.ProfileVersion = 4
	other := migrationStartApprovalIntent("tenant-a", "operator@example.test", "plan-1", "authority-1", "digest-1", changed)
	if strings.Join(other.EvidenceRefs, "\n") == joined {
		t.Fatal("a changed profile revision produced the same approval intent")
	}
	for _, edit := range []func(*migrationGatedMember){
		func(m *migrationGatedMember) { m.IssuingAuthorityID = "ca-2" },
		func(m *migrationGatedMember) { m.TargetID = "target-other" },
		func(m *migrationGatedMember) { m.TargetRevision = "rev-8" },
		func(m *migrationGatedMember) { m.PredecessorFingerprint = "fingerprint-other" },
	} {
		changed = append([]migrationGatedMember(nil), gated...)
		edit(&changed[0])
		other = migrationStartApprovalIntent("tenant-a", "operator@example.test", "plan-1", "authority-1", "digest-1", changed)
		if strings.Join(other.EvidenceRefs, "\n") == joined {
			t.Fatal("a changed issuer, target, or predecessor reused the approval intent")
		}
	}
}
