package server

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
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// JOURNEY-003 acceptance: the governed request/approve journey requires a
// distinct approver principal, and the product now serves the admin path to
// create and retire that principal. This drives the running server over bearer
// API-token auth: only the initial platform-admin token is test-seeded like a
// first bootstrap credential; member onboarding, approver token minting, approval,
// and offboarding all go through /api/v1/access/*.
func TestServedAccessAdminOnboardsAndOffboardsDistinctApprover(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "platform-admin", []string{
		string(authz.AccessRead), string(authz.AccessWrite),
		string(authz.AccessRoleAssign),
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.CertsRequest), string(authz.CertsIssue),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store:            st,
		Log:              log,
		DefaultProfile:   "tls-server",
		EnablePolicyGate: true,
		RequireApproval:  true,
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{
			OIDCEnabled: true, TenantClaim: "org", GroupsClaim: "groups",
			DefaultRoles: []string{"viewer"},
			TenantMappings: []api.AuthTenantMapping{{
				Group: "pki-approvers", TenantID: tenantID, Roles: []string{"operator"},
			}},
		})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rolesCode, rolesBody := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", adminToken, "", nil)
	if rolesCode != http.StatusOK || !bytes.Contains(rolesBody, []byte(`"name":"operator"`)) || !bytes.Contains(rolesBody, []byte(`"certs:issue"`)) {
		t.Fatalf("role catalog = %d body=%s; want operator role with certs:issue", rolesCode, rolesBody)
	}
	oidcCode, oidcBody := doBearer(t, ts, http.MethodGet, "/api/v1/access/oidc-mapping", adminToken, "", nil)
	if oidcCode != http.StatusOK || !bytes.Contains(oidcBody, []byte(`"groups_claim":"groups"`)) || !bytes.Contains(oidcBody, []byte(`"group":"pki-approvers"`)) {
		t.Fatalf("OIDC mapping status = %d body=%s; want served group mapping", oidcCode, oidcBody)
	}

	upsertMember(t, ts, adminToken, "requester", []string{"ra-officer"})
	upsertMember(t, ts, adminToken, "issuer", []string{"operator"})
	upsertMember(t, ts, adminToken, "approver-one", []string{"operator"})
	upsertMember(t, ts, adminToken, "approver-two", []string{"operator"})

	requesterToken := createServedToken(t, ts, adminToken, "requester", []string{string(authz.IdentitiesWrite), string(authz.CertsRequest)})
	issuerToken := createServedToken(t, ts, adminToken, "issuer", []string{string(authz.IdentitiesWrite), string(authz.CertsIssue), string(authz.CertsRequest)})
	approverOneToken := createServedToken(t, ts, adminToken, "approver-one", []string{string(authz.CertsIssue)})
	approverTwoToken := createServedToken(t, ts, adminToken, "approver-two", []string{string(authz.CertsIssue)})

	identID := createIdentityWithToken(t, ts, requesterToken, owner.ID)
	if code, body := transitionIdentityWithToken(t, ts, issuerToken, identID, "issued", "issuer-first-attempt"); code != http.StatusForbidden {
		t.Fatalf("issue before distinct approvals = %d, want 403; body=%s", code, body)
	}
	if code, body := approveIdentityWithToken(t, ts, approverOneToken, identID, "approve-one"); code != http.StatusOK {
		t.Fatalf("first distinct approval = %d, want 200; body=%s", code, body)
	}
	if code, body := approveIdentityWithToken(t, ts, approverTwoToken, identID, "approve-two"); code != http.StatusOK {
		t.Fatalf("second distinct approval = %d, want 200; body=%s", code, body)
	}
	if code, body := transitionIdentityWithToken(t, ts, issuerToken, identID, "issued", "issuer-approved"); code != http.StatusOK {
		t.Fatalf("issue after distinct approvals = %d, want 200; body=%s", code, body)
	}

	code, offboardBody := doBearer(t, ts, http.MethodPost, "/api/v1/access/members/approver-one/offboard", adminToken, "offboard-approver-one", map[string]string{"reason": "left pki team"})
	if code != http.StatusOK || !bytes.Contains(offboardBody, []byte(`"revoked_token_count":1`)) {
		t.Fatalf("offboard approver = %d body=%s; want one revoked token", code, offboardBody)
	}
	code, revokedBody := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", approverOneToken, "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked approver token role read = %d, want 401; body=%s", code, revokedBody)
	}
	code, listed := doBearer(t, ts, http.MethodGet, "/api/v1/access/api-tokens?subject=approver-one&include_revoked=true", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(listed, []byte(`"revoked_at"`)) {
		t.Fatalf("revoked token metadata = %d body=%s; want revoked_at evidence", code, listed)
	}

	var sawOffboard bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == projections.EventTenantMemberOffboarded && ev.TenantID == tenantID && bytes.Contains(ev.Data, []byte(`"subject":"approver-one"`)) {
			sawOffboard = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawOffboard {
		t.Fatal("tenant.member.offboarded event for approver-one was not recorded")
	}
}

func seedServedAPIToken(t *testing.T, ctx context.Context, st *store.Store, tenantID, subject string, scopes []string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate API token: %v", err)
	}
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{TenantID: tenantID, TokenHash: hash, Subject: subject, Scopes: scopes}); err != nil {
		t.Fatalf("seed API token: %v", err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}

func upsertMember(t *testing.T, ts *httptest.Server, adminToken, subject string, roles []string) {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, adminToken, "member-"+subject, map[string]any{
		"display_name": subject, "roles": roles, "source": "manual",
	})
	if code != http.StatusOK {
		t.Fatalf("upsert member %s = %d, want 200; body=%s", subject, code, body)
	}
}

func createServedToken(t *testing.T, ts *httptest.Server, adminToken, subject string, scopes []string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/api-tokens", adminToken, "token-"+subject, map[string]any{
		"subject": subject, "scopes": scopes,
	})
	if code != http.StatusCreated {
		t.Fatalf("create token for %s = %d, want 201; body=%s", subject, code, body)
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &got); err != nil || !strings.HasPrefix(got.Token, auth.TokenPrefix) {
		t.Fatalf("decode created token for %s: token=%q err=%v body=%s", subject, got.Token, err, body)
	}
	return got.Token
}

func createIdentityWithToken(t *testing.T, ts *httptest.Server, token, ownerID string) string {
	t.Helper()
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/identities", token, "identity-requester", map[string]any{
		"kind": "x509_certificate", "name": "svc.example.test", "owner_id": ownerID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create identity as requester = %d, want 201; body=%s", code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id: %v body=%s", err, body)
	}
	return got.ID
}

func transitionIdentityWithToken(t *testing.T, ts *httptest.Server, token, identityID, to, idem string) (int, []byte) {
	t.Helper()
	return doBearer(t, ts, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions", token, idem, map[string]string{"to": to, "reason": "journey acceptance"})
}

func approveIdentityWithToken(t *testing.T, ts *httptest.Server, token, identityID, idem string) (int, []byte) {
	t.Helper()
	return doBearer(t, ts, http.MethodPost, "/api/v1/identities/"+identityID+"/approvals", token, idem, map[string]string{"action": "issue"})
}

func doBearer(t *testing.T, ts *httptest.Server, method, path, token, idem string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}
