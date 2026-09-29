// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// F263: the evaluation stacks give every OIDC session default_roles=admin. An
// operator who then sets a member to viewer in People and roles must get a viewer
// session, not admin plus viewer. A member record that names roles replaces the
// sign-in roles on every request; one that names none leaves them in place.
func TestServedMemberRolesReplaceSignInRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenantID = "f2630000-0000-4000-8000-000000000263"
		clientID = "trstctl-ui"
	)
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)

	idp := newMockIdP(t, clientID)
	for _, sub := range []string{"reader", "mapped", "profile-only", "newcomer"} {
		idp.registerUser("code-"+sub, sub, map[string]any{"tenant": tenantID})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	srv := buildServer(t, ctx, dsn, config.OIDC{
		Enabled:           true,
		Issuer:            idp.issuer,
		ClientID:          clientID,
		AuthEndpoint:      idp.issuer + "/authorize",
		TokenEndpoint:     idp.issuer + "/token",
		RedirectURI:       baseURL + "/auth/callback",
		JWKSJSON:          idp.jwksJSON(t),
		SessionSecretFile: t.TempDir() + "/session.secret",
		SessionTTL:        "1h",
		TenantClaim:       "tenant",
		ClaimIsTenant:     true,
		DefaultRoles:      []string{"admin"},
		TenantMappings:    []config.TenantMapping{{Subject: "mapped", TenantID: tenantID, Roles: []string{"operator"}}},
	})
	defer func() { _ = srv.Shutdown(context.Background()) }()
	registerServerTestTenant(t, srv.store, srv.log, tenantID, "F263 member roles")
	ts := httptest.NewUnstartedServer(srv.Handler())
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	defer ts.Close()

	adminToken := seedServedAPIToken(t, ctx, srv.store, tenantID, "people-admin", []string{"access:read", "access:write", "access:role.assign"})
	upsertMember(t, ts, adminToken, "reader", []string{"viewer"})
	upsertMember(t, ts, adminToken, "mapped", []string{"viewer"})
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/profile-only", adminToken, "member-profile-only",
		map[string]any{"display_name": "Profile only", "source": "manual"}); code != http.StatusOK {
		t.Fatalf("upsert role-less member = %d, want 200; body=%s", code, body)
	}

	sessions := map[string]http.CookieJar{}
	for _, sub := range []string{"reader", "mapped", "profile-only", "newcomer"} {
		jar, _ := cookiejar.New(nil)
		servedOIDCLoginF263(t, baseURL, idp, jar, "code-"+sub)
		sessions[sub] = jar
	}
	for _, tc := range []struct {
		subject     string
		wantRoles   []string
		auditRead   int
		whyExpected string
	}{
		{"reader", []string{"viewer"}, http.StatusForbidden, "member role viewer replaces default_roles admin"},
		{"mapped", []string{"viewer"}, http.StatusForbidden, "member role viewer replaces the subject mapping's operator"},
		{"profile-only", []string{"admin"}, http.StatusOK, "a member record naming no roles keeps the sign-in roles"},
		{"newcomer", []string{"admin"}, http.StatusOK, "no member record keeps the sign-in roles"},
	} {
		roles, perms := servedSessionMeF263(t, baseURL, sessions[tc.subject])
		if !slices.Equal(roles, tc.wantRoles) {
			t.Errorf("%s session roles = %v, want %v (%s)", tc.subject, roles, tc.wantRoles, tc.whyExpected)
		}
		if tc.wantRoles[0] == "viewer" && (slices.Contains(perms, "*") || slices.Contains(perms, "access:role.assign")) {
			t.Errorf("%s viewer session permissions = %v, want no wildcard or role assignment", tc.subject, perms)
		}
		if code := servedSessionGetF263(t, baseURL, sessions[tc.subject], "/api/v1/audit/events?limit=1"); code != tc.auditRead {
			t.Errorf("%s audit read = %d, want %d (%s)", tc.subject, code, tc.auditRead, tc.whyExpected)
		}
	}

	// Member changes still take effect on the next request of an existing session.
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/reader", adminToken, "member-reader-auditor",
		map[string]any{"display_name": "reader", "roles": []string{"auditor"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("change reader to auditor = %d, want 200; body=%s", code, body)
	}
	if roles, _ := servedSessionMeF263(t, baseURL, sessions["reader"]); !slices.Equal(roles, []string{"auditor"}) {
		t.Fatalf("reader roles after member change = %v, want [auditor] without re-login", roles)
	}
	if code := servedSessionGetF263(t, baseURL, sessions["reader"], "/api/v1/audit/events?limit=1"); code != http.StatusOK {
		t.Fatalf("reader audit read after becoming auditor = %d, want 200", code)
	}
}

func servedOIDCLoginF263(t *testing.T, baseURL string, idp *mockIdP, jar http.CookieJar, loginAs string) {
	t.Helper()
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	drainBody(resp)
	idpURL, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(idpURL.String(), idp.issuer+"/authorize") {
		t.Fatalf("GET /auth/login = %d Location=%q, want 302 to the IdP", resp.StatusCode, resp.Header.Get("Location"))
	}
	q := idpURL.Query()
	q.Set("login_as", loginAs)
	idpURL.RawQuery = q.Encode()
	resp, err = client.Get(idpURL.String())
	if err != nil {
		t.Fatalf("GET IdP /authorize: %v", err)
	}
	drainBody(resp)
	resp, err = client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	drainBody(resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/callback for %s = %d, want 302 (session established)", loginAs, resp.StatusCode)
	}
}

func servedSessionMeF263(t *testing.T, baseURL string, jar http.CookieJar) ([]string, []string) {
	t.Helper()
	resp, err := (&http.Client{Jar: jar}).Get(baseURL + "/auth/me")
	if err != nil {
		t.Fatalf("GET /auth/me: %v", err)
	}
	body := drainBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var me struct {
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("decode /auth/me: %v; body=%s", err, body)
	}
	return me.Roles, me.Permissions
}

func servedSessionGetF263(t *testing.T, baseURL string, jar http.CookieJar, path string) int {
	t.Helper()
	resp, err := (&http.Client{Jar: jar}).Get(baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	drainBody(resp)
	return resp.StatusCode
}
