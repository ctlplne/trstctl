package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedNHIOverPrivilegeCAPPOST01EndToEnd proves CAP-POST-01 is served:
// the public API analyzes managed and discovered NHIs, detects granted-vs-used
// over-privilege, and returns usage-driven least-privilege recommendations.
func TestServedNHIOverPrivilegeCAPPOST01EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	ctx := context.Background()

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "Platform Team", Email: "platform@example.test"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}

	seedIdentity := func(id, name string, attrs map[string]any) {
		t.Helper()
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatalf("marshal attrs for %s: %v", id, err)
		}
		if err := h.store.UpsertIdentity(ctx, store.Identity{
			ID: id, TenantID: h.tenant, Kind: store.KindAPIKey, Name: name,
			OwnerID: owner.ID, Status: "deployed", Attributes: raw,
		}); err != nil {
			t.Fatalf("seed identity %s: %v", id, err)
		}
	}

	seedIdentity("22222222-2222-2222-2222-22222222a001", "payments-admin-token", map[string]any{
		"granted_scopes": []string{"repo:read", "repo:write", "admin:org", "secrets:write"},
		"used_scopes":    []string{"repo:read"},
		"last_used_at":   "2026-05-01T00:00:00Z",
	})
	seedIdentity("22222222-2222-2222-2222-22222222a002", "read-only-token", map[string]any{
		"granted_scopes": []string{"repo:read"},
		"used_scopes":    []string{"repo:read"},
		"last_used_at":   "2026-05-02T00:00:00Z",
	})
	seedDiscoveryPostureFinding(t, h.store, h.tenant, map[string]any{
		"credential_kind":      "oauth_app",
		"principal":            "legacy-github-app",
		"granted_permissions":  []string{"repo", "admin:org", "workflow"},
		"observed_permissions": []string{"repo"},
		"last_used_at":         "2026-04-01T00:00:00Z",
	})

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/overprivilege", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("NHI over-privilege posture: status %d body %s", status, body)
	}
	var got struct {
		Capability string   `json:"capability"`
		Coverage   []string `json:"coverage"`
		Summary    struct {
			TotalAnalyzed       int `json:"total_analyzed"`
			Overprivileged      int `json:"overprivileged"`
			LeastPrivilegePlans int `json:"least_privilege_plans"`
			UnusedGrants        int `json:"unused_grants"`
		} `json:"summary"`
		Findings []struct {
			InventoryID       string   `json:"inventory_id"`
			DisplayName       string   `json:"display_name"`
			Kind              string   `json:"kind"`
			Source            string   `json:"source"`
			Severity          string   `json:"severity"`
			FindingTypes      []string `json:"finding_types"`
			GrantedScopes     []string `json:"granted_scopes"`
			UsedScopes        []string `json:"used_scopes"`
			UnusedScopes      []string `json:"unused_scopes"`
			RecommendedScopes []string `json:"recommended_scopes"`
			Recommendation    string   `json:"recommendation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode posture response: %v (%s)", err, body)
	}
	if got.Capability != "CAP-POST-01" {
		t.Fatalf("capability = %q, want CAP-POST-01", got.Capability)
	}
	for _, want := range []string{"managed_identities", "discovery_findings", "usage_driven_scope_delta", "least_privilege_recommendations"} {
		if !containsString(got.Coverage, want) {
			t.Fatalf("coverage %v missing %q", got.Coverage, want)
		}
	}
	if got.Summary.TotalAnalyzed != 3 || got.Summary.Overprivileged != 2 || got.Summary.LeastPrivilegePlans != 2 || got.Summary.UnusedGrants != 5 {
		t.Fatalf("summary = %+v, want 3 analyzed / 2 overprivileged / 2 plans / 5 unused", got.Summary)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings count = %d body %s, want 2", len(got.Findings), body)
	}
	byName := map[string]struct {
		unused []string
		used   []string
		source string
	}{}
	for _, f := range got.Findings {
		byName[f.DisplayName] = struct {
			unused []string
			used   []string
			source string
		}{unused: f.UnusedScopes, used: f.RecommendedScopes, source: f.Source}
		if f.Severity == "" || !containsString(f.FindingTypes, "unused_grants") || f.Recommendation == "" {
			t.Fatalf("finding lacks severity/type/recommendation: %+v", f)
		}
	}
	payments, ok := byName["payments-admin-token"]
	if !ok || !containsString(payments.unused, "admin:org") || !containsString(payments.unused, "secrets:write") || !containsString(payments.used, "repo:read") {
		t.Fatalf("managed identity recommendation = %+v, want unused admin/secrets and repo:read plan", payments)
	}
	discovered, ok := byName["legacy-github-app"]
	if !ok || discovered.source != "discovery_finding" || !containsString(discovered.unused, "admin:org") || !containsString(discovered.used, "repo") {
		t.Fatalf("discovered NHI recommendation = %+v, want discovery finding with admin:org removal and repo plan", discovered)
	}
}

// TestServedNHIStaleDormantCAPPOST02EndToEnd proves CAP-POST-02 is served:
// the public API detects stale, unused, orphaned, and dormant NHIs from managed
// and discovered inventory evidence without treating fresh active NHIs as gaps.
func TestServedNHIStaleDormantCAPPOST02EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "nhi:read")
	ctx := context.Background()
	now := time.Now().UTC()

	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "DevEx", Email: "devex@example.test"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}

	seedIdentity := func(id, name string, attrs map[string]any) {
		t.Helper()
		raw, err := json.Marshal(attrs)
		if err != nil {
			t.Fatalf("marshal attrs for %s: %v", id, err)
		}
		if err := h.store.UpsertIdentity(ctx, store.Identity{
			ID: id, TenantID: h.tenant, Kind: store.KindAPIKey, Name: name,
			OwnerID: owner.ID, Status: "deployed", Attributes: raw,
		}); err != nil {
			t.Fatalf("seed identity %s: %v", id, err)
		}
	}

	seedIdentity("22222222-2222-2222-2222-22222222c001", "stale-ci-token", map[string]any{
		"last_seen_at": now.AddDate(0, 0, -220).Format(time.RFC3339),
		"last_used_at": now.AddDate(0, 0, -220).Format(time.RFC3339),
	})
	seedIdentity("22222222-2222-2222-2222-22222222c002", "active-ci-token", map[string]any{
		"last_seen_at": now.AddDate(0, 0, -5).Format(time.RFC3339),
		"last_used_at": now.AddDate(0, 0, -5).Format(time.RFC3339),
	})
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant,
		"22222222-2222-2222-2222-22222222d001",
		"22222222-2222-2222-2222-22222222d002",
		"22222222-2222-2222-2222-22222222d003",
		now.AddDate(0, 0, -420),
		map[string]any{
			"credential_kind": "personal_access_token",
			"principal":       "dormant-github-pat",
			"owner":           "devex",
			"last_used_at":    now.AddDate(0, 0, -420).Format(time.RFC3339),
		})
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant,
		"22222222-2222-2222-2222-22222222e001",
		"22222222-2222-2222-2222-22222222e002",
		"22222222-2222-2222-2222-22222222e003",
		now.AddDate(0, 0, -160),
		map[string]any{
			"credential_kind": "service_account",
			"principal":       "orphaned-build-sa",
			"created_at":      now.AddDate(0, 0, -160).Format(time.RFC3339),
		})

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/stale", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("NHI stale posture: status %d body %s", status, body)
	}
	var got struct {
		Capability string   `json:"capability"`
		Coverage   []string `json:"coverage"`
		Summary    struct {
			TotalAnalyzed   int `json:"total_analyzed"`
			Findings        int `json:"findings"`
			Stale           int `json:"stale"`
			Dormant         int `json:"dormant"`
			Unused          int `json:"unused"`
			Orphaned        int `json:"orphaned"`
			Recommendations int `json:"recommendations"`
		} `json:"summary"`
		Findings []struct {
			InventoryID     string     `json:"inventory_id"`
			DisplayName     string     `json:"display_name"`
			Source          string     `json:"source"`
			Severity        string     `json:"severity"`
			FindingTypes    []string   `json:"finding_types"`
			OwnerStatus     string     `json:"owner_status"`
			ActivityAgeDays int        `json:"activity_age_days"`
			Recommendation  string     `json:"recommendation"`
			LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode stale posture response: %v (%s)", err, body)
	}
	if got.Capability != "CAP-POST-02" {
		t.Fatalf("capability = %q, want CAP-POST-02", got.Capability)
	}
	for _, want := range []string{"managed_identities", "discovery_findings", "stale_activity", "unused_no_activity", "orphaned_detection", "dormant_detection"} {
		if !containsString(got.Coverage, want) {
			t.Fatalf("coverage %v missing %q", got.Coverage, want)
		}
	}
	if got.Summary.TotalAnalyzed != 5 || got.Summary.Findings != 3 || got.Summary.Stale != 2 || got.Summary.Dormant != 1 || got.Summary.Unused != 1 || got.Summary.Orphaned != 1 || got.Summary.Recommendations != 3 {
		t.Fatalf("summary = %+v, want 5 analyzed / 3 findings / 2 stale / 1 dormant / 1 unused / 1 orphaned / 3 recommendations", got.Summary)
	}
	byName := map[string]struct {
		types       []string
		ownerStatus string
		source      string
	}{}
	for _, f := range got.Findings {
		byName[f.DisplayName] = struct {
			types       []string
			ownerStatus string
			source      string
		}{types: f.FindingTypes, ownerStatus: f.OwnerStatus, source: f.Source}
		if f.Severity == "" || f.Recommendation == "" {
			t.Fatalf("finding lacks severity/recommendation: %+v", f)
		}
	}
	if stale := byName["stale-ci-token"]; !containsString(stale.types, "stale_activity") || stale.ownerStatus != "owned" {
		t.Fatalf("stale managed finding = %+v, want stale owned managed identity", stale)
	}
	if dormant := byName["dormant-github-pat"]; dormant.source != "discovery_finding" || !containsString(dormant.types, "dormant_activity") {
		t.Fatalf("dormant discovered finding = %+v, want discovery dormant finding", dormant)
	}
	orphaned := byName["orphaned-build-sa"]
	if orphaned.source != "discovery_finding" || orphaned.ownerStatus != "orphaned" || !containsString(orphaned.types, "unused_no_activity") || !containsString(orphaned.types, "orphaned_nhi") {
		t.Fatalf("orphaned unused finding = %+v, want orphaned unused discovery finding", orphaned)
	}
}

func seedDiscoveryPostureFinding(t *testing.T, s *store.Store, tenantID string, metadata map[string]any) {
	seedDiscoveryPostureFindingWithIDs(t, s, tenantID,
		"22222222-2222-2222-2222-22222222b001",
		"22222222-2222-2222-2222-22222222b002",
		"22222222-2222-2222-2222-22222222b003",
		time.Now().UTC(),
		metadata)
}

func seedDiscoveryPostureFindingWithIDs(t *testing.T, s *store.Store, tenantID, sourceID, runID, findingID string, discoveredAt time.Time, metadata map[string]any) {
	t.Helper()
	ctx := context.Background()
	sourceSuffix := sourceID[len(sourceID)-4:]
	findingSuffix := findingID[len(findingID)-4:]
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal discovery metadata: %v", err)
	}
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantID, Kind: "nhi", Name: "nhi-posture-" + sourceSuffix,
			Config: []byte(`{}`), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantID, SourceID: sourceID, Status: "queued", CreatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID: findingID, TenantID: tenantID, RunID: runID, SourceID: sourceID,
			Kind: "non_human_identity", Ref: "nhi://" + findingSuffix, Provenance: "oauth-saas",
			Fingerprint: "fp-nhi-" + findingSuffix, RiskScore: 84, Metadata: raw,
			DiscoveredAt: discoveredAt.UTC(),
		})
	}); err != nil {
		t.Fatalf("seed discovery finding: %v", err)
	}
}
