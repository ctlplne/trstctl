package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// TestAPITokenScopesEnforced is the acceptance: an API token presented as a
// bearer credential is authenticated by its hash and its scopes are enforced by
// the RBAC guard — it may do what its scopes allow and nothing more.
func TestAPITokenScopesEnforced(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	ctx := context.Background()

	// Mint a read-only (identities:read) token for tenantA and persist its hash.
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: hash, Subject: "ci-bot", Scopes: []string{"identities:read"},
	}); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	bearer := secrettext.String(raw)
	secret.Wipe(raw)

	// The token carries its own tenant and scopes — no tenant/role headers. A read
	// is allowed.
	if st, _, body := do(t, srv, "GET", "/api/v1/identities", reqOpts{bearer: bearer}); st != http.StatusOK {
		t.Fatalf("token GET identities = %d, want 200: %s", st, body)
	}
	// A write is outside the token's scope.
	st, hdr, body := do(t, srv, "POST", "/api/v1/identities", reqOpts{
		bearer: bearer, idem: "tok1",
		body: map[string]any{"kind": "x509_certificate", "name": "x", "owner_id": idOwner},
	})
	if st != http.StatusForbidden {
		t.Fatalf("token POST identities = %d, want 403: %s", st, body)
	}
	assertProblem(t, hdr, body, http.StatusForbidden)

	// An unknown token is rejected.
	if st, _, _ := do(t, srv, "GET", "/api/v1/identities", reqOpts{bearer: "trst_deadbeefdeadbeefdeadbeef"}); st != http.StatusUnauthorized {
		t.Errorf("unknown token GET = %d, want 401", st)
	}
}
