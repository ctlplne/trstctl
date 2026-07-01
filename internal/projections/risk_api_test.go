package projections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/risk"
	"trstctl.com/trstctl/internal/store"
)

// seedRiskInventory plants three certificates whose risk should rank clearly:
// a wildcard, orphaned, never-rotated, near-expiry cert (highest); a mid cert;
// and a fresh, owned, recently-rotated, single-name cert (lowest).
func seedRiskInventory(t *testing.T, s *store.Store) (highID, midID, lowID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "app"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}

	high, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "CN=*.prod.example.com", SANs: []string{"*.prod.example.com"},
		Issuer: "CN=CA", Serial: "01", Fingerprint: "fp-high", KeyAlgorithm: "ECDSA",
		NotBefore: tptr(now.Add(-300 * 24 * time.Hour)), NotAfter: tptr(now.Add(20 * 24 * time.Hour)),
		DeploymentLocation: "prod-lb", Source: "import", Status: "active", // OwnerID nil (orphaned), RenewedAt nil (never rotated)
	})
	if err != nil {
		t.Fatalf("seed high: %v", err)
	}

	mid, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=svc.example.com",
		SANs: []string{"svc.example.com", "svc2.example.com"}, Issuer: "CN=CA", Serial: "02",
		Fingerprint: "fp-mid", KeyAlgorithm: "ECDSA",
		NotBefore: tptr(now.Add(-180 * 24 * time.Hour)), NotAfter: tptr(now.Add(185 * 24 * time.Hour)),
		RenewedAt: tptr(now.Add(-180 * 24 * time.Hour)), DeploymentLocation: "svc-host",
		Source: "import", Status: "active",
	})
	if err != nil {
		t.Fatalf("seed mid: %v", err)
	}

	low, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=app.internal", SANs: []string{"app.internal"},
		Issuer: "CN=CA", Serial: "03", Fingerprint: "fp-low", KeyAlgorithm: "ECDSA",
		NotBefore: tptr(now.Add(-24 * time.Hour)), NotAfter: tptr(now.Add(364 * 24 * time.Hour)),
		RenewedAt: tptr(now.Add(-24 * time.Hour)), Source: "import", Status: "active",
	})
	if err != nil {
		t.Fatalf("seed low: %v", err)
	}
	return high.ID, mid.ID, low.ID
}

// TestRiskScoreInventoryRanksSensibly is the S6.6 acceptance over real
// PostgreSQL: scores compute over the inventory and rank sensibly.
func TestRiskScoreInventoryRanksSensibly(t *testing.T) {
	srv, s := newGraphAPI(t)
	_ = srv
	highID, midID, lowID := seedRiskInventory(t, s)

	scores, err := risk.ScoreInventory(context.Background(), s, tenantA)
	if err != nil {
		t.Fatalf("ScoreInventory: %v", err)
	}
	if len(scores) != 3 {
		t.Fatalf("scored %d credentials, want 3", len(scores))
	}
	// Returned ranked by score descending.
	if scores[0].CredentialID != highID || scores[2].CredentialID != lowID {
		t.Errorf("ranking = %s > %s > %s, want %s ... %s",
			scores[0].CredentialID, scores[1].CredentialID, scores[2].CredentialID, highID, lowID)
	}
	if !(scores[0].Score > scores[1].Score && scores[1].Score > scores[2].Score) {
		t.Errorf("scores not strictly ordered: %.1f %.1f %.1f", scores[0].Score, scores[1].Score, scores[2].Score)
	}
	_ = midID
	// The riskiest carries the signals that made it risky.
	top := scores[0]
	if top.Privilege != risk.PrivilegeHigh || top.OwnerActive || top.Components.Rotation != 1 {
		t.Errorf("top credential signals = %+v", top)
	}
}

// TestRiskAPISortsAndFilters is the S6.6 acceptance for the API surface: the
// score is sortable and filterable.
func TestRiskAPISortsAndFilters(t *testing.T) {
	srv, s := newGraphAPI(t)
	highID, _, lowID := seedRiskInventory(t, s)

	list := func(query string, o reqOpts) []risk.CredentialRisk {
		t.Helper()
		o.tenant = tenantA
		status, _, body := do(t, srv, http.MethodGet, "/api/v1/risk/credentials"+query, o)
		if status != http.StatusOK {
			t.Fatalf("GET risk%s = %d: %s", query, status, body)
		}
		var resp struct {
			Credentials []risk.CredentialRisk `json:"credentials"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.Credentials
	}

	// Default: ranked by score, riskiest first.
	all := list("", reqOpts{})
	if len(all) != 3 || all[0].CredentialID != highID || all[2].CredentialID != lowID {
		t.Fatalf("default ranking wrong: %+v", credIDs(all))
	}

	// Sort by expiry: the near-expiry cert comes first.
	byExpiry := list("?sort=expiry", reqOpts{})
	if byExpiry[0].CredentialID != highID {
		t.Errorf("sort=expiry first = %s, want high (soonest expiry)", byExpiry[0].CredentialID)
	}

	// Filter by score: a threshold between the mid and low scores drops the low.
	threshold := (all[1].Score + all[2].Score) / 2
	filtered := list("?min_score="+ftoa(threshold), reqOpts{})
	if len(filtered) != 2 {
		t.Errorf("min_score filter kept %d, want 2", len(filtered))
	}
	for _, c := range filtered {
		if c.CredentialID == lowID {
			t.Error("min_score filter should have dropped the low-risk credential")
		}
	}

	// Filter by privilege: only the wildcard (High) credential.
	highPriv := list("?privilege=high", reqOpts{})
	if len(highPriv) != 1 || highPriv[0].CredentialID != highID {
		t.Errorf("privilege=high = %v, want [high]", credIDs(highPriv))
	}

	// A bad sort key is a 400.
	if status, _, _ := do(t, srv, http.MethodGet, "/api/v1/risk/credentials?sort=nope", reqOpts{tenant: tenantA}); status != http.StatusBadRequest {
		t.Errorf("bad sort status = %d, want 400", status)
	}
}

// TestRiskAPIRequiresPermission proves the endpoint is guarded by risk:read.
func TestRiskAPIRequiresPermission(t *testing.T) {
	srv, s := newGraphAPI(t)
	seedRiskInventory(t, s)
	if status, _, _ := do(t, srv, http.MethodGet, "/api/v1/risk/credentials", reqOpts{tenant: tenantA, roles: "viewer"}); status != http.StatusOK {
		t.Errorf("viewer = %d, want 200", status)
	}
	if status, _, _ := do(t, srv, http.MethodGet, "/api/v1/risk/credentials", reqOpts{tenant: tenantA, roles: "auditor"}); status != http.StatusForbidden {
		t.Errorf("auditor = %d, want 403", status)
	}
}

// TestContextualRiskPrioritizationCAPPOST05 proves CAP-POST-05 is served: the
// API prioritizes credentials with blast-radius context, including affected
// resources and CBOM crypto assets, not only the raw credential score.
func TestContextualRiskPrioritizationCAPPOST05(t *testing.T) {
	srv, s := newGraphAPI(t)
	ctx := context.Background()
	now := time.Now()

	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	payments, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=payments-api.prod", SANs: []string{"payments-api.prod", "payments-api.internal"},
		Issuer: "CN=CA", Serial: "ctx-01", Fingerprint: "fp-context-payments", KeyAlgorithm: "ECDSA",
		NotBefore: tptr(now.Add(-300 * 24 * time.Hour)), NotAfter: tptr(now.Add(30 * 24 * time.Hour)),
		RenewedAt: tptr(now.Add(-240 * 24 * time.Hour)), DeploymentLocation: "payments-db",
		Source: "import", Status: "active",
	})
	if err != nil {
		t.Fatalf("seed payments cert: %v", err)
	}
	if _, err := s.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, OwnerID: &owner.ID, Subject: "CN=dev-api", SANs: []string{"dev-api"},
		Issuer: "CN=CA", Serial: "ctx-02", Fingerprint: "fp-context-dev", KeyAlgorithm: "ECDSA",
		NotBefore: tptr(now.Add(-24 * time.Hour)), NotAfter: tptr(now.Add(365 * 24 * time.Hour)),
		RenewedAt: tptr(now.Add(-24 * time.Hour)), DeploymentLocation: "dev-api",
		Source: "import", Status: "active",
	}); err != nil {
		t.Fatalf("seed dev cert: %v", err)
	}
	if err := s.UpsertIdentity(ctx, store.Identity{
		ID:        "00000000-0000-0000-0000-00000000a017",
		TenantID:  tenantA,
		Kind:      store.KindAPIKey,
		Name:      "github-release-api-key",
		OwnerID:   owner.ID,
		Status:    "deployed",
		NotBefore: tptr(now.Add(-200 * 24 * time.Hour)),
		NotAfter:  tptr(now.Add(90 * 24 * time.Hour)),
		Attributes: json.RawMessage(`{
			"deployment_target": "release-runner",
			"granted_scopes": ["repo", "workflow"],
			"observed_scopes": ["repo"],
			"last_rotated_at": "2025-01-01T00:00:00Z",
			"sensitivity": "high"
		}`),
	}); err != nil {
		t.Fatalf("seed API-key identity: %v", err)
	}
	seedContextualDiscoveryFinding(t, s, now)
	for _, asset := range []store.CryptoAsset{
		{TenantID: tenantA, Kind: "tls-protocol", Location: "payments-db", Protocol: "TLSv1.0", Strength: "weak", OutOfPolicy: true, Reasons: []string{"legacy protocol"}},
		{TenantID: tenantA, Kind: "cipher", Location: "payments-db", Cipher: "3DES", Strength: "weak", OutOfPolicy: true, Reasons: []string{"weak cipher"}},
		{TenantID: tenantA, Kind: "algorithm", Location: "payments-db", Algorithm: "RSA", KeyBits: 2048, Strength: "classical", QuantumVulnerable: true, Reasons: []string{"quantum vulnerable"}},
	} {
		if _, err := s.UpsertCryptoAsset(ctx, asset); err != nil {
			t.Fatalf("upsert crypto asset: %v", err)
		}
	}

	status, _, body := do(t, srv, http.MethodGet, "/api/v1/risk/contextual-priorities", reqOpts{tenant: tenantA})
	if status != http.StatusOK {
		t.Fatalf("GET contextual priorities = %d: %s", status, body)
	}
	var resp struct {
		Capability string `json:"capability"`
		Summary    struct {
			TotalAnalyzed     int `json:"total_analyzed"`
			Priorities        int `json:"priorities"`
			HighBlastRadius   int `json:"high_blast_radius"`
			WeakCryptoContext int `json:"weak_crypto_context"`
			Recommendations   int `json:"recommendations"`
		} `json:"summary"`
		Priorities []struct {
			Rank                   int      `json:"rank"`
			CredentialID           string   `json:"credential_id"`
			Severity               string   `json:"severity"`
			ContextualScore        float64  `json:"contextual_score"`
			BaseScore              float64  `json:"base_score"`
			BlastRadius            int      `json:"blast_radius"`
			ResourceBlastRadius    int      `json:"resource_blast_radius"`
			CryptoAssetBlastRadius int      `json:"crypto_asset_blast_radius"`
			PriorityReasons        []string `json:"priority_reasons"`
			EvidenceRefs           []string `json:"evidence_refs"`
			RecommendedAction      string   `json:"recommended_action"`
		} `json:"priorities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode contextual priorities: %v", err)
	}
	if resp.Capability != "CAP-POST-05" {
		t.Fatalf("capability = %q, want CAP-POST-05", resp.Capability)
	}
	if resp.Summary.TotalAnalyzed < 4 || resp.Summary.Priorities < 4 || resp.Summary.HighBlastRadius < 1 || resp.Summary.WeakCryptoContext < 1 || resp.Summary.Recommendations < 4 {
		t.Fatalf("summary = %+v, want at least analyzed/priorities/high-blast/weak-context/recommendations = 4/4/1/1/4", resp.Summary)
	}
	if len(resp.Priorities) < 4 {
		t.Fatalf("priorities = %d, want at least 4", len(resp.Priorities))
	}
	byID := map[string]struct {
		Rank                   int      `json:"rank"`
		CredentialID           string   `json:"credential_id"`
		Severity               string   `json:"severity"`
		ContextualScore        float64  `json:"contextual_score"`
		BaseScore              float64  `json:"base_score"`
		BlastRadius            int      `json:"blast_radius"`
		ResourceBlastRadius    int      `json:"resource_blast_radius"`
		CryptoAssetBlastRadius int      `json:"crypto_asset_blast_radius"`
		PriorityReasons        []string `json:"priority_reasons"`
		EvidenceRefs           []string `json:"evidence_refs"`
		RecommendedAction      string   `json:"recommended_action"`
	}{}
	for _, p := range resp.Priorities {
		byID[p.CredentialID] = p
	}
	if _, ok := byID["00000000-0000-0000-0000-00000000a017"]; !ok {
		t.Fatalf("contextual priorities missing non-certificate API-key identity: %+v", resp.Priorities)
	}
	if _, ok := byID["discovery:00000000-0000-0000-0000-00000000d017"]; !ok {
		t.Fatalf("contextual priorities missing discovered token finding: %+v", resp.Priorities)
	}
	paymentsPriority, ok := byID[payments.ID]
	if !ok {
		t.Fatalf("contextual priorities missing payments cert %s: %+v", payments.ID, resp.Priorities)
	}
	if paymentsPriority.ContextualScore <= paymentsPriority.BaseScore {
		t.Fatalf("contextual score %.2f should exceed base score %.2f when blast radius and weak crypto context are present", paymentsPriority.ContextualScore, paymentsPriority.BaseScore)
	}
	if paymentsPriority.BlastRadius < 4 || paymentsPriority.ResourceBlastRadius != 1 || paymentsPriority.CryptoAssetBlastRadius < 3 {
		t.Fatalf("payments blast radius = total %d resources %d crypto assets %d, want >=4 / 1 / >=3", paymentsPriority.BlastRadius, paymentsPriority.ResourceBlastRadius, paymentsPriority.CryptoAssetBlastRadius)
	}
	if !hasString(paymentsPriority.PriorityReasons, "high_blast_radius") || !hasString(paymentsPriority.PriorityReasons, "weak_crypto_context") {
		t.Fatalf("priority reasons = %v, want high_blast_radius and weak_crypto_context", paymentsPriority.PriorityReasons)
	}
	if len(paymentsPriority.EvidenceRefs) == 0 || paymentsPriority.RecommendedAction == "" || paymentsPriority.Severity == "" || paymentsPriority.Rank == 0 {
		t.Fatalf("payments priority missing evidence/action/severity/rank: %+v", paymentsPriority)
	}
}

func seedContextualDiscoveryFinding(t *testing.T, s *store.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID:        "00000000-0000-0000-0000-00000000c017",
			TenantID:  tenantA,
			Kind:      "apikey",
			Name:      "ci-token-source",
			Config:    json.RawMessage(`{"mode":"metadata_only"}`),
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID:          "00000000-0000-0000-0000-00000000b017",
			TenantID:    tenantA,
			SourceID:    "00000000-0000-0000-0000-00000000c017",
			Status:      "succeeded",
			RequestedBy: "test",
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID:           "00000000-0000-0000-0000-00000000d017",
			TenantID:     tenantA,
			RunID:        "00000000-0000-0000-0000-00000000b017",
			SourceID:     "00000000-0000-0000-0000-00000000c017",
			Kind:         "api_key",
			Ref:          "ci/deploy-token",
			Provenance:   "release-runner",
			Fingerprint:  "fp-discovered-token",
			RiskScore:    88,
			Metadata:     json.RawMessage(`{"credential_kind":"token","display_name":"ci deploy token","last_used_at":"2026-06-01T00:00:00Z","owner_status":"orphaned"}`),
			DiscoveredAt: now,
		})
	})
	if err != nil {
		t.Fatalf("seed contextual discovery finding: %v", err)
	}
}

func credIDs(rs []risk.CredentialRisk) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.CredentialID
	}
	return out
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 4, 64) }

func hasString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
