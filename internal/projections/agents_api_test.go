// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
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
	calls             int
	tenants           []string
	allowedIdentities []string
	// roles records the capability grant each mint carried (epic A2), so a test
	// can prove the handler passes the operator's grant through rather than
	// dropping it on the way to the authority.
	roles [][]string
}

func (s *stubTokenIssuer) IssueBootstrapToken(ctx context.Context, tenantID, allowedIdentity string) ([]byte, error) {
	return s.IssueBootstrapTokenWithRoles(ctx, tenantID, allowedIdentity, nil)
}

func (s *stubTokenIssuer) IssueBootstrapTokenWithRoles(
	_ context.Context,
	tenantID, allowedIdentity string,
	roles []string,
) ([]byte, error) {
	s.calls++
	s.tenants = append(s.tenants, tenantID)
	s.allowedIdentities = append(s.allowedIdentities, allowedIdentity)
	s.roles = append(s.roles, roles)
	return []byte("bootstrap-token-fixed"), nil
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
		api.WithAgentEnrollmentConnection("agents.example.test:9443", "agents.example.test"),
		api.WithAgentEnrollmentRenewal(true),
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

// TestPreviewEnrollmentPlanIsEffectFree proves the console can show the exact
// identity, certificate roles, connection endpoint, permissions, and secret
// boundary before the one-time bootstrap token exists. Preview and execution
// share the role/relay authority, but only execution calls the issuer.
func TestPreviewEnrollmentPlanIsEffectFree(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write", "agents:relay.grant")

	code, body := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens/preview", token, "",
		map[string]any{"allowed_identity": " edge-01 ", "roles": []string{"network", "host"}})
	if code != http.StatusOK {
		t.Fatalf("POST enrollment preview = %d, want 200 (body %v)", code, body)
	}
	if issuer.calls != 0 {
		t.Fatalf("effect-free preview minted %d tokens, want 0", issuer.calls)
	}
	if body["ready"] != true || body["side_effects"] != false {
		t.Fatalf("preview readiness/effects = %v/%v, want true/false", body["ready"], body["side_effects"])
	}
	if body["renewal_ready"] != true || body["renewal_path"] != "/enroll/renewal" {
		t.Fatalf("preview renewal lifecycle = %v / %v, want ready /enroll/renewal", body["renewal_ready"], body["renewal_path"])
	}
	if auth, _ := body["renewal_authentication"].(string); !strings.Contains(auth, "verified") || !strings.Contains(auth, "mTLS") {
		t.Fatalf("preview renewal authentication = %q, want verified mTLS client certificate", auth)
	}
	if body["allowed_identity"] != "edge-01" || body["agent_server"] != "agents.example.test:9443" || body["agent_server_name"] != "agents.example.test" {
		t.Fatalf("preview exact identity/connection = %v", body)
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 2 || roles[0] != "host" || roles[1] != "network" {
		t.Fatalf("preview roles = %v, want [host network]", body["roles"])
	}
	permissions, _ := body["required_permissions"].([]any)
	if len(permissions) != 2 || permissions[0] != "agents:write" || permissions[1] != "agents:relay.grant" {
		t.Fatalf("preview permissions = %v, want agents:write + agents:relay.grant", body["required_permissions"])
	}
	blocked, _ := body["blocked_reasons"].([]any)
	if len(blocked) != 0 {
		t.Fatalf("ready preview blockers = %v, want none", blocked)
	}
	if handling, _ := body["data_handling"].(string); !strings.Contains(handling, "one-time token") || !strings.Contains(handling, "not") {
		t.Fatalf("preview data boundary = %q, want explicit no-token boundary", handling)
	}
}

// TestEnrollmentMintFailsClosedWithoutRenewalLifecycle is the F54 safety gate:
// publishing an agent dial address is not enough. A newly enrolled machine would
// eventually strand itself if the current-certificate mTLS renewal listener were
// absent, so preview and execution must share the same server-owned blocker.
func TestEnrollmentMintFailsClosedWithoutRenewalLifecycle(t *testing.T) {
	issuer := &stubTokenIssuer{}
	s := newStore(t)
	log := openLog(t)
	a := api.New(
		s,
		orchestrator.NewIdempotency(s),
		orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s)),
		api.WithAgentEnrollment(issuer),
		api.WithAgentEnrollmentConnection("agents.example.test:9443", "agents.example.test"),
	)
	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)
	token := mintToken(t, s, "agents:write")

	previewCode, preview := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens/preview", token, "",
		map[string]any{"allowed_identity": "edge-no-renewal", "roles": []string{"host"}})
	if previewCode != http.StatusOK || preview["ready"] != false || preview["renewal_ready"] != false {
		t.Fatalf("preview without renewal = %d / %v, want 200 blocked lifecycle", previewCode, preview)
	}
	blocked, _ := preview["blocked_reasons"].([]any)
	if len(blocked) == 0 || !strings.Contains(blocked[0].(string), "renew") {
		t.Fatalf("preview blockers = %v, want exact renewal remedy", blocked)
	}

	code, body := doJSON(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "no-renewal-key")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("mint without renewal lifecycle = %d / %v, want 503", code, body)
	}
	if issuer.calls != 0 {
		t.Fatalf("blocked lifecycle minted %d tokens, want 0", issuer.calls)
	}
}

func TestPreviewEnrollmentPlanFailsClosedWithoutPublishedConnection(t *testing.T) {
	issuer := &stubTokenIssuer{}
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
	token := mintToken(t, s, "agents:write")

	code, body := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens/preview", token, "",
		map[string]any{"allowed_identity": "edge-01", "roles": []string{"host"}})
	if code != http.StatusOK || body["ready"] != false || body["side_effects"] != false {
		t.Fatalf("missing-connection preview = %d / %v, want 200 blocked and effect-free", code, body)
	}
	if issuer.calls != 0 {
		t.Fatalf("blocked preview minted %d tokens, want 0", issuer.calls)
	}
	blocked, _ := body["blocked_reasons"].([]any)
	if len(blocked) == 0 || !strings.Contains(blocked[0].(string), "public agent address") {
		t.Fatalf("blocked reasons = %v, want exact public-address remedy", blocked)
	}
}

func TestPreviewEnrollmentPlanEnforcesRelayGrant(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write")

	code, _ := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens/preview", token, "",
		map[string]any{"allowed_identity": "edge-relay-01", "roles": []string{"host", "network"}})
	if code != http.StatusForbidden {
		t.Fatalf("relay preview without agents:relay.grant = %d, want 403", code)
	}
	if issuer.calls != 0 {
		t.Fatalf("refused relay preview minted %d tokens, want 0", issuer.calls)
	}
}

// doJSONBody is doJSON with a request body, for the routes whose behavior depends
// on what the operator asked for rather than only on who they are.
func doJSONBody(
	t *testing.T,
	srv *httptest.Server,
	method, path, token, idempotencyKey string,
	payload any,
) (int, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
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

// TestEnrollmentTokenCarriesTheOperatorsGrant: the roles an operator picks reach
// the authority, and the response reports the grant that will actually be stamped
// rather than echoing what was typed (epic A2).
func TestEnrollmentTokenCarriesTheOperatorsGrant(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write", "agents:relay.grant")

	code, body := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-roles-1",
		map[string]any{"roles": []string{"network", "host"}})
	if code != http.StatusCreated {
		t.Fatalf("POST enrollment-tokens = %d, want 201 (body %v)", code, body)
	}
	if len(issuer.roles) != 1 || len(issuer.roles[0]) != 2 ||
		issuer.roles[0][0] != "host" || issuer.roles[0][1] != "network" {
		t.Fatalf("authority received roles %v, want [host network]", issuer.roles)
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 2 {
		t.Fatalf("response roles = %v, want two", body["roles"])
	}
}

// TestEnrollmentTokenRelayRoleNeedsItsOwnPermission is the separation this epic
// added: agents:write enrolls host agents all day, but placing a relay — which
// holds the credentials for the appliances it fronts — is a distinct authority.
func TestEnrollmentTokenRelayRoleNeedsItsOwnPermission(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write") // no agents:relay.grant

	code, _ := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-roles-2",
		map[string]any{"roles": []string{"network"}})
	if code != http.StatusForbidden {
		t.Fatalf("relay grant without agents:relay.grant = %d, want 403", code)
	}
	if issuer.calls != 0 {
		t.Errorf("authority minted %d tokens for a refused relay grant, want 0", issuer.calls)
	}

	// The same caller can still enroll a host agent, so the gate is on the
	// capability and not on the route.
	hostCode, _ := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-roles-3",
		map[string]any{"roles": []string{"host"}})
	if hostCode != http.StatusCreated {
		t.Fatalf("host-only mint without the relay permission = %d, want 201", hostCode)
	}
}

// TestEnrollmentTokenRejectsAnUnknownRole: an operator who asks for a capability
// that does not exist is told so, rather than handed a token that quietly grants
// less than they believe.
func TestEnrollmentTokenRejectsAnUnknownRole(t *testing.T) {
	issuer := &stubTokenIssuer{}
	srv, s := newAgentsAPI(t, issuer)
	token := mintToken(t, s, "agents:write", "agents:relay.grant")

	code, _ := doJSONBody(t, srv, http.MethodPost, "/api/v1/agents/enrollment-tokens", token, "key-roles-4",
		map[string]any{"roles": []string{"admin"}})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown role = %d, want 400", code)
	}
	if issuer.calls != 0 {
		t.Errorf("authority minted %d tokens for an unknown role, want 0", issuer.calls)
	}
}
