package projections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

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

func credIDs(rs []risk.CredentialRisk) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.CredentialID
	}
	return out
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 4, 64) }
