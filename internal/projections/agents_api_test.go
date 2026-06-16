package projections_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// stubTokenIssuer is a fake agent BootstrapTokenIssuer. It records how many times
// it minted a token (so the test can prove idempotent replay does not mint a
// second one) and the tenant each mint was attributed to (so the test can prove
// the served handler passes the caller's tenant through — WIRE-003/AN-1).
type stubTokenIssuer struct {
	calls   int
	tenants []string
}

func (s *stubTokenIssuer) IssueBootstrapToken(_ context.Context, tenantID string) (string, error) {
	s.calls++
	s.tenants = append(s.tenants, tenantID)
	return "bootstrap-token-fixed", nil
}

// newAgentsAPI builds the real API over embedded PostgreSQL with the agent
// enrollment bridge wired, and returns an HTTP server plus the store.
func newAgentsAPI(t *testing.T, issuer api.BootstrapTokenIssuer) (*httptest.Server, *store.Store) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	a := api.New(
		s,
		orchestrator.NewIdempotency(s),
		orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)),
		api.WithAgentEnrollment(issuer),
	)
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	return srv, s
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, token, idempotencyKey string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s %s body %q: %v", method, path, body, err)
		}
	}
	return resp.StatusCode, out
}

// TestAgentsListReturnsInventory is part of the S7.3 wizard acceptance ("a first
// agent registers"): a registered agent is visible through GET /api/v1/agents so
// the wizard can detect it.
func TestAgentsListReturnsInventory(t *testing.T) {
	srv, s := newAgentsAPI(t, &stubTokenIssuer{})
	token := mintToken(t, s, "agents:read")

	if err := s.UpsertAgent(context.Background(), store.Agent{
		ID: "11111111-1111-1111-1111-111111111111", TenantID: tenantA,
		Name: "edge-01", Status: "online", Version: "0.1.0",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	code, body := doJSON(t, srv, http.MethodGet, "/api/v1/agents", token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /agents = %d, want 200 (body %v)", code, body)
	}
	agents, ok := body["agents"].([]any)
	if !ok || len(agents) != 1 {
		t.Fatalf("expected one agent, got %v", body["agents"])
	}
	first, _ := agents[0].(map[string]any)
	if first["name"] != "edge-01" {
		t.Errorf("agent name = %v, want edge-01", first["name"])
	}
}

// TestAgentsListRequiresReadScope: a token lacking agents:read is refused.
func TestAgentsListRequiresReadScope(t *testing.T) {
	srv, s := newAgentsAPI(t, &stubTokenIssuer{})
	token := mintToken(t, s, "owners:read") // wrong scope
	code, _ := doJSON(t, srv, http.MethodGet, "/api/v1/agents", token, "")
	if code != http.StatusForbidden {
		t.Fatalf("GET /agents with wrong scope = %d, want 403", code)
	}
}

// TestCreateEnrollmentTokenMintsOnce is the other half of the wizard's agent
// step: the UI mints a one-time bootstrap token to build the install command.
// The mint is idempotent (AN-5) — replaying the same key returns the original
// token and does not mint a second one.
func TestCreateEnrollmentTokenMintsOnce(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write")

	code, body := doJSON(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-1")
	if code != http.StatusCreated {
		t.Fatalf("POST enrollment-tokens = %d, want 201 (body %v)", code, body)
	}
	if body["token"] != "bootstrap-token-fixed" {
		t.Fatalf("token = %v, want bootstrap-token-fixed", body["token"])
	}

	// Replay with the same idempotency key: same token, no second mint.
	code2, body2 := doJSON(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-1")
	if code2 != http.StatusCreated || body2["token"] != "bootstrap-token-fixed" {
		t.Fatalf("replay = %d / %v, want 201 / bootstrap-token-fixed", code2, body2["token"])
	}
	if issuer.calls != 1 {
		t.Errorf("issuer minted %d times, want exactly 1 (idempotent replay)", issuer.calls)
	}
	// The served handler attributed the mint to the caller's tenant (WIRE-003/AN-1):
	// the bearer token (mintToken) is scoped to tenantA, so that is the tenant the
	// bootstrap token — and the agent certificate it later yields — is bound to.
	if len(issuer.tenants) != 1 || issuer.tenants[0] != tenantA {
		t.Errorf("enrollment token minted for tenant(s) %v, want exactly [%s]", issuer.tenants, tenantA)
	}
}

// TestCreateEnrollmentTokenRequiresWriteScope: a read-only token cannot mint.
func TestCreateEnrollmentTokenRequiresWriteScope(t *testing.T) {
	srv, s := newAgentsAPI(t, &stubTokenIssuer{})
	token := mintToken(t, s, "agents:read")
	code, _ := doJSON(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-2")
	if code != http.StatusForbidden {
		t.Fatalf("mint with read-only scope = %d, want 403", code)
	}
}

// TestEnrollmentTokenUnconfigured: when no issuer is wired, the endpoint reports
// the capability is unavailable rather than panicking.
func TestEnrollmentTokenUnconfigured(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	a := api.New(s, orchestrator.NewIdempotency(s), orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)))
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	token := mintToken(t, s, "agents:write")

	code, body := doJSON(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-3")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("mint with no issuer = %d, want 503 (body %v)", code, body)
	}
	if d, _ := body["detail"].(string); !strings.Contains(d, "enroll") {
		t.Errorf("detail = %q, want it to mention enrollment", d)
	}
}
