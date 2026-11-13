// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// A170-L3: an abusive OAuth grant detection is posture family oauth_abuse,
// with the detection and its reasons as finding types and the provider named,
// so an nhi_posture rule acts when the detection lands; the OAuth
// remediations apply only to a discovered OAuth grant row.
func TestNHIPostureOAuthAbuseIsAFamilyARuleCanActOnA170L3(t *testing.T) {
	meta, err := json.Marshal(map[string]any{
		"provider": "okta", "app_id": "0oa-exfil", "principal": "00u-alice", "detection_kind": "malicious_oauth_grant",
		"abuse_reasons": []string{"provider_threat_signal", "dangerous_wildcard_scope"},
	})
	if err != nil {
		t.Fatal(err)
	}
	abuse := nhiInventoryItem{ID: "finding/11111111-1111-1111-1111-111111111111", Kind: "oauth_grant_abuse",
		Source: "discovery_finding", DisplayName: "00u-alice", Status: "open", RiskScore: 95, Metadata: meta}
	facts, families, ok := nhiPostureFactsForItem(abuse, time.Now().UTC(), nil)
	if !ok || !slices.Contains(facts.Posture, "oauth_abuse") || facts.Severity != "critical" || facts.RiskScore != 95 ||
		facts.Provider != "okta" || facts.Managed {
		t.Fatalf("abuse facts = %+v ok=%v", facts, ok)
	}
	for _, typ := range []string{"malicious_oauth_grant", "provider_threat_signal", "dangerous_wildcard_scope"} {
		if !slices.Contains(facts.FindingTypes, typ) {
			t.Fatalf("finding types %v omit %s", facts.FindingTypes, typ)
		}
	}
	if action, detail := nhiPostureActionFor("revoke_oauth_grant", facts, families); action != nhiPostureActionRevokeOAuthGrant || detail != "" {
		t.Fatalf("revoke_oauth_grant on an abusive grant = %s %q", action, detail)
	}
	if action, _ := nhiPostureActionFor("block_oauth_app", facts, families); action != nhiPostureActionBlockOAuthApp {
		t.Fatalf("block_oauth_app on an abusive grant = %s", action)
	}

	// A grant the detector did not flag is no oauth_abuse row of its own.
	plainMeta, err := json.Marshal(map[string]any{"provider": "okta", "app_id": "0oa-calendar", "principal": "00u-bob"})
	if err != nil {
		t.Fatal(err)
	}
	if facts, _, ok := nhiPostureFactsForItem(nhiInventoryItem{ID: "finding/22222222-2222-2222-2222-222222222222", Kind: "oauth_app",
		Source: "discovery_finding", Metadata: plainMeta}, time.Now().UTC(), nil); ok && slices.Contains(facts.Posture, "oauth_abuse") {
		t.Fatalf("an unflagged grant is oauth_abuse: %+v", facts)
	}
	// The same detection kind on a row that is not a discovery finding is not
	// a detection.
	if _, ok := nhiOAuthAbuseForItem(nhiInventoryItem{ID: "identity/x", Kind: "oauth_app", Source: "managed_identity", Metadata: meta}); ok {
		t.Fatal("a managed identity's metadata raised oauth_abuse")
	}

	// A managed identity or a non-OAuth finding cannot take an OAuth remediation.
	managed := facts
	managed.InventoryID, managed.Kind, managed.Managed = "identity/11111111-1111-1111-1111-111111111111", "api_key", true
	if action, detail := nhiPostureActionFor("revoke_oauth_grant", managed, families); action != nhiPostureActionNotApplicable ||
		!strings.Contains(detail, "discovered OAuth grant") {
		t.Fatalf("revoke_oauth_grant on a managed identity = %s %q", action, detail)
	}
	secretFinding := facts
	secretFinding.Kind = "secret"
	if action, _ := nhiPostureActionFor("block_oauth_app", secretFinding, families); action != nhiPostureActionNotApplicable {
		t.Fatalf("block_oauth_app on a secret finding = %s", action)
	}
	if nhiPostureOAuthProviderAction(nhiPostureActionBlockOAuthApp) != "block_app" ||
		nhiPostureOAuthProviderAction(nhiPostureActionRevokeOAuthGrant) != "revoke_grant" {
		t.Fatal("OAuth remediations do not map to the operator's provider actions")
	}
	for risk, want := range map[int]string{95: "critical", 90: "critical", 85: "high", 70: "high", 50: "medium", 10: "low"} {
		if got := nhiOAuthAbuseSeverity(risk); got != want {
			t.Fatalf("severity(%d) = %s; want %s", risk, got, want)
		}
	}
}

// The plan's last run for an OAuth remediation is the finding's latest
// provider action of that kind, as the finding records it.
func TestNHIPostureOAuthLastRunIsTheFindingsProviderActionA170L3(t *testing.T) {
	meta, err := json.Marshal(map[string]any{"provider_actions": map[string]any{
		"revoke_grant": map[string]any{"status": "failed", "request_id": "33333333-3333-3333-3333-333333333333",
			"updated_at": "2026-11-13T06:00:00.5Z", "detail": "status 401"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	item := nhiInventoryItem{ID: "finding/x", Metadata: meta}
	run := nhiPostureOAuthLastRun(item, "revoke_grant")
	if run == nil || run.ID != "33333333-3333-3333-3333-333333333333" || run.Status != "failed" || run.Phase != "revoke_grant" ||
		run.PlaybookID != "" || !run.CreatedAt.Equal(time.Date(2026, 11, 13, 6, 0, 0, 500_000_000, time.UTC)) {
		t.Fatalf("last run = %+v", run)
	}
	if nhiPostureOAuthLastRun(item, "block_app") != nil {
		t.Fatal("a revoke stood in for a block")
	}
	if nhiPostureOAuthLastRun(nhiInventoryItem{ID: "finding/y", Metadata: json.RawMessage(`{}`)}, "revoke_grant") != nil {
		t.Fatal("a finding without provider actions reported a run")
	}
}
