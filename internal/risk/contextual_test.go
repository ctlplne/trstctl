// SPDX-License-Identifier: MPL-2.0

package risk

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func TestContextualPriorityRaisesBlastRadiusWeakCryptoAndOwnershipReasons(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	base := CredentialRisk{
		CredentialID: "cred-1",
		Subject:      "svc-payments",
		Kind:         "api_key",
		Privilege:    PrivilegeHigh,
		Sensitivity:  SensitivityHigh,
		OwnerActive:  false,
		ExpiresAt:    now.Add(10 * 24 * time.Hour),
		Score:        58.4,
		Components:   Components{Rotation: 0.9},
		GraphNodeID:  "id:api-key-1",
		EvidenceRefs: []string{"identity:api-key-1"},
	}
	weak := graph.Node{ID: "crypto:rsa1024", Kind: graph.KindCryptoAsset, Attrs: map[string]string{"strength": "weak"}}
	impact := graph.Impact{
		Node: graph.Node{ID: "id:api-key-1", Kind: graph.KindCredential},
		Affected: []graph.Node{
			{ID: "res:db", Kind: graph.KindResource},
			{ID: "res:queue", Kind: graph.KindResource},
			{ID: "wl:worker", Kind: graph.KindWorkload},
			{ID: "cred:peer", Kind: graph.KindCredential},
			weak,
		},
		ByKind: map[graph.NodeKind][]graph.Node{
			graph.KindResource:    {{ID: "res:db", Kind: graph.KindResource}, {ID: "res:queue", Kind: graph.KindResource}},
			graph.KindWorkload:    {{ID: "wl:worker", Kind: graph.KindWorkload}},
			graph.KindCredential:  {{ID: "cred:peer", Kind: graph.KindCredential}},
			graph.KindCryptoAsset: {weak},
		},
	}

	got := contextualPriority(base, impact, now)
	if got.Severity != "critical" || got.ContextualScore != 100 {
		t.Fatalf("contextual priority = score %.1f severity %s, want capped critical", got.ContextualScore, got.Severity)
	}
	for _, want := range []string{"high_blast_radius", "weak_crypto_context", "privileged_credential", "orphaned_owner", "near_expiry", "stale_rotation"} {
		if !slices.Contains(got.PriorityReasons, want) {
			t.Fatalf("priority reasons missing %q: %#v", want, got.PriorityReasons)
		}
	}
	if got.WeakCryptoContext != 1 || got.BlastRadius != len(impact.Affected) {
		t.Fatalf("blast/weak context not preserved: %+v", got)
	}
	if !slices.Contains(got.EvidenceRefs, "graph:blast-radius:id:api-key-1") || !slices.Contains(got.EvidenceRefs, "cbom:weak-crypto-assets:1") {
		t.Fatalf("evidence refs missing graph/cbom context: %#v", got.EvidenceRefs)
	}
	if got.RecommendedAction == "" || got.RecommendedAction == contextualAction(10, 0, 0, true) {
		t.Fatalf("unexpected recommended action: %q", got.RecommendedAction)
	}
}

func TestContextualScorersNormalizeNHIKindsAndMetadata(t *testing.T) {
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	g := graph.New()
	for _, n := range []graph.Node{
		{ID: "id:id-1", Kind: graph.KindCredential},
		{ID: "ssh:ssh-1", Kind: graph.KindCredential},
		{ID: "disc:disc-1", Kind: graph.KindCredential},
		{ID: "res:prod-db", Kind: graph.KindResource},
		{ID: "res:prod-admin", Kind: graph.KindResource},
	} {
		g.AddNode(n)
	}
	g.AddEdge(graph.Edge{From: "id:id-1", To: "res:prod-db", Type: graph.EdgeGrantsAccess})
	g.AddEdge(graph.Edge{From: "ssh:ssh-1", To: "res:prod-admin", Type: graph.EdgeGrantsAccess})
	g.AddEdge(graph.Edge{From: "disc:disc-1", To: "res:prod-db", Type: graph.EdgeDeployedTo})

	attrs := mustJSON(t, map[string]any{
		"granted_scopes":  []any{"read:all", "admin:*"},
		"privilege":       "root",
		"sensitivity":     "confidential",
		"owner_status":    "orphaned",
		"last_rotated_at": now.Add(-400 * 24 * time.Hour).Format(time.RFC3339),
	})
	identity := scoreIdentity(g, store.Identity{
		ID: "id-1", Kind: store.KindAPIKey, Name: "ci-token", OwnerID: "owner-1",
		Attributes: attrs, CreatedAt: now.Add(-500 * 24 * time.Hour),
	}, now)
	if identity.Kind != "api_key" || identity.Privilege != PrivilegeCritical || identity.Sensitivity != SensitivityHigh || identity.OwnerActive {
		t.Fatalf("identity risk did not honor NHI metadata: %+v", identity)
	}
	if identity.Exposure != 1 || identity.GraphNodeID != "id:id-1" {
		t.Fatalf("identity graph exposure = %d node=%q", identity.Exposure, identity.GraphNodeID)
	}

	ssh := scoreSSHKey(g, store.SSHKey{ID: "ssh-1", Fingerprint: "SHA256:abc", Comment: "deploy key", StandingAccess: true, CreatedAt: now.Add(-90 * 24 * time.Hour)}, now)
	if ssh.Kind != "ssh_key" || ssh.Privilege != PrivilegeHigh || ssh.Sensitivity != SensitivityHigh || !ssh.OwnerActive {
		t.Fatalf("ssh risk did not reflect standing access: %+v", ssh)
	}

	finding := scoreDiscoveryFinding(g, store.DiscoveryFinding{
		ID: "disc-1", Kind: "non_human_identity", Ref: "oauth-grant/payments", RiskScore: 91,
		Metadata: mustJSON(t, map[string]any{
			"credential_kind": "oauth_app",
			"display_name":    "Payments OAuth grant",
			"owner":           "platform",
			"expires_at":      now.Add(12 * time.Hour).Format(time.RFC3339),
			"roles":           "workflow:write,deploy",
		}),
		DiscoveredAt: now.Add(-24 * time.Hour),
	}, now)
	if finding.Kind != "oauth_app" || finding.Subject != "Payments OAuth grant" || finding.Score < 91 {
		t.Fatalf("discovery finding risk did not normalize metadata/risk floor: %+v", finding)
	}
	if finding.Privilege != PrivilegeHigh || finding.Sensitivity != SensitivityHigh || !finding.OwnerActive {
		t.Fatalf("discovery finding privilege/sensitivity/owner = %+v", finding)
	}
}

func TestContextualMetadataHelpersHandleMalformedAndDelimitedValues(t *testing.T) {
	if got := metadataMap(json.RawMessage(`not-json`)); len(got) != 0 {
		t.Fatalf("metadataMap malformed = %#v, want empty", got)
	}
	meta := metadataMap(mustJSON(t, map[string]any{
		"scopes":          "read, write , admin",
		"roles":           []any{"viewer", " deploy "},
		"owner_status":    "missing",
		"service_owner":   "team-a",
		"created_at":      "2026-07-01T00:00:00Z",
		"emptyish":        "   ",
		"numeric_display": 42,
	}))
	if got := metadataStrings(meta, "scopes", "roles"); !slices.Contains(got, "write") || !slices.Contains(got, "deploy") {
		t.Fatalf("metadataStrings = %#v, want delimited string and array values", got)
	}
	if !metadataOwnerOrphaned(meta) || metadataOwnerActive(meta) {
		t.Fatalf("owner helpers did not let orphaned status override owner fields")
	}
	if got := metadataString(meta, "numeric_display"); got != "42" {
		t.Fatalf("metadataString numeric = %q, want 42", got)
	}
	if got := metadataTime(meta, "missing", "created_at"); got.IsZero() {
		t.Fatalf("metadataTime did not parse fallback RFC3339 value")
	}
	for raw, want := range map[string]string{
		"PAT":             "personal_access_token",
		"tls-certificate": "certificate",
		"unknown":         "credential",
		"ssh_certificate": "ssh_key",
	} {
		if got := normalizeCredentialKind(raw); got != want {
			t.Fatalf("normalizeCredentialKind(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSortByContextualPriorityOrdersScoreBlastRadiusAndID(t *testing.T) {
	items := []ContextualPriority{
		{CredentialID: "c", ContextualScore: 70, BlastRadius: 2},
		{CredentialID: "b", ContextualScore: 90, BlastRadius: 1},
		{CredentialID: "a", ContextualScore: 90, BlastRadius: 3},
	}
	SortByContextualPriority(items)
	if got := []string{items[0].CredentialID, items[1].CredentialID, items[2].CredentialID}; got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("SortByContextualPriority order = %v", got)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
