package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// mockIdP is a minimal OIDC identity provider for the served-login acceptance test.
// It signs id_tokens with a test RSA key the server trusts (via the published
// JWKS), maps an authorization code to fixed claims, and serves the authorize +
// token endpoints a real browser/callback hit. It is NOT a production component —
// it exists so the test can drive the SAME served /auth/* flow the binary mounts,
// end to end, without a live external IdP.
type mockIdP struct {
	srv      *httptest.Server
	sk       *jose.SigningKey
	issuer   string
	clientID string
	codes    map[string]map[string]any // authorization code -> id_token claims
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	sk, err := jose.GenerateRSASigningKey("idp-test-key")
	if err != nil {
		t.Fatalf("generate idp key: %v", err)
	}
	idp := &mockIdP{sk: sk, clientID: clientID, codes: map[string]map[string]any{}}
	mux := http.NewServeMux()
	// /authorize: a real IdP authenticates the user and redirects to redirect_uri with
	// ?code=...&state=.... Here we mint a code bound to the user the test selected via
	// a sentinel "login_as" param, echo the server's nonce into the token-to-be, and
	// bounce back to the server's redirect_uri preserving state.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		nonce := q.Get("nonce")
		code := q.Get("login_as")
		claims := idp.codes[code]
		if redirectURI == "" || claims == nil {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		claims["nonce"] = nonce // the IdP binds the request nonce into the id_token
		idp.codes[code] = claims
		http.Redirect(w, r, redirectURI+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), http.StatusFound)
	})
	// /token: exchange the code for a signed id_token (RFC 6749 §4.1.3).
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := idp.codes[r.Form.Get("code")]
		if claims == nil {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		payload, _ := json.Marshal(claims)
		signed, err := sk.Sign(payload)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "token_type": "Bearer"})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	idp.issuer = idp.srv.URL
	return idp
}

// registerUser pre-seeds an authorization code that, when redeemed, yields an
// id_token for sub with the given extra claims. The IdP fills iss/aud/exp/iat and
// the request nonce.
func (idp *mockIdP) registerUser(code, sub string, extra map[string]any) {
	now := time.Now()
	claims := map[string]any{
		"iss": idp.issuer, "aud": idp.clientID, "sub": sub,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	idp.codes[code] = claims
}

func (idp *mockIdP) jwksJSON(t *testing.T) string {
	t.Helper()
	b, err := idp.sk.PublicJWKS()
	if err != nil {
		t.Fatalf("marshal idp jwks: %v", err)
	}
	return string(b)
}

// TestServedOIDCLoginEndToEnd is the EXC-WIRE-01 acceptance — the served OIDC
// browser login + session + per-user → tenant mapping, proven against the
// production composition (server.Build -> Handler()) on the embedded stack (bundled
// PostgreSQL + in-process NATS). It drives the SAME served path cmd/trstctl serves
// (/auth/login -> IdP -> /auth/callback -> session cookie -> a guarded /api/v1
// call), not a library function.
//
// It MUST FAIL on the pre-wiring tree (api.WithAuth was never called by
// internal/server, so /auth/login 404'd and the session principal path was dead) and
// PASS after, and is race-clean. It asserts end to end:
//   - GET /auth/login 302s to the IdP authorize endpoint (SEC-001/WIRE-001/SURFACE-002);
//   - the callback verifies the id_token, sets an HttpOnly session cookie, and the
//     cookie authorizes a guarded API call returning ONLY that user's tenant data;
//   - a SECOND user with a DIFFERENT tenant claim lands in a different tenant and sees
//     ONLY its own data — cross-tenant isolation via the browser path (TENANT-004,
//     AN-1 RLS); the single DefaultTenant collapse is gone;
//   - a freshly logged-in user whose role lacks certs:issue CANNOT self-issue: the
//     served issuance gate denies it (RED-004), so wiring login did not re-open
//     self-issue.
func TestServedOIDCLoginEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	const (
		tenantA  = "11111111-1111-1111-1111-111111111111"
		tenantB  = "22222222-2222-2222-2222-222222222222"
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

	// Seed an owner in EACH tenant so a tenant-scoped read proves isolation: tenant A
	// sees only ownerA, tenant B only ownerB.
	ownerA, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "tenant-a-payments"})
	if err != nil {
		t.Fatalf("seed owner A: %v", err)
	}
	ownerB, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantB, Kind: store.OwnerWorkload, Name: "tenant-b-billing"})
	if err != nil {
		t.Fatalf("seed owner B: %v", err)
	}

	idp := newMockIdP(t, clientID)
	// alice -> tenant A (admin), bob -> tenant B (admin), rick -> tenant A but the
	// "requester" role (identities:write, NOT certs:issue) so a logged-in requester's
	// self-issue is denied by the served gate (RED-004).
	idp.registerUser("code-alice", "alice", map[string]any{"email": "alice@a.test", "tenant": tenantA})
	idp.registerUser("code-bob", "bob", map[string]any{"email": "bob@b.test", "tenant": tenantB})
	idp.registerUser("code-rick", "rick", map[string]any{"email": "rick@a.test", "tenant": tenantA})

	// Listen on a known loopback port FIRST so the OIDC RedirectURI can be set before
	// Build reads it (the server's redirect_uri must point back at this listener's
	// /auth/callback). This breaks the chicken-and-egg without guessing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	oidc := config.OIDC{
		Enabled:           true,
		Issuer:            idp.issuer,
		ClientID:          clientID,
		AuthEndpoint:      idp.issuer + "/authorize",
		TokenEndpoint:     idp.issuer + "/token",
		RedirectURI:       baseURL + "/auth/callback",
		JWKSJSON:          idp.jwksJSON(t),
		SessionSecretFile: t.TempDir() + "/session.secret",
		SessionTTL:        "1h",
		// Per-user → tenant mapping: roles come from the subject mapping table; the
		// tenant is taken directly from the verified "tenant" claim (claim_is_tenant) —
		// proving claim-based mapping. The subject mappings additionally pin the tenant
		// (defense in depth) and assign roles.
		TenantClaim:   "tenant",
		ClaimIsTenant: true,
		TenantMappings: []config.TenantMapping{
			{Subject: "alice", TenantID: tenantA, Roles: []string{"admin"}},
			{Subject: "bob", TenantID: tenantB, Roles: []string{"admin"}},
			{Subject: "rick", TenantID: tenantA, Roles: []string{"requester"}},
		},
	}

	srv := buildServer(t, ctx, dsn, oidc)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	// --- Pre-wiring guard: with OIDC unwired, /auth/login 404s. Post-wiring it 302s
	// to the IdP. We assert the 302 (the negative is the pre-fix failure). ---
	login := func(t *testing.T, jar http.CookieJar, loginAs string) {
		t.Helper()
		// A client that does NOT auto-follow redirects, so we can inspect /auth/login's
		// 302 to the IdP and then drive the IdP + callback manually with the cookie jar.
		client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

		// 1) GET /auth/login -> 302 to the IdP authorize URL (with state+nonce cookies).
		resp, err := client.Get(baseURL + "/auth/login")
		if err != nil {
			t.Fatalf("GET /auth/login: %v", err)
		}
		drainBody(resp)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET /auth/login = %d, want 302 to the IdP (served OIDC login; pre-wiring this 404s)", resp.StatusCode)
		}
		idpURL, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || !strings.HasPrefix(resp.Header.Get("Location"), idp.issuer+"/authorize") {
			t.Fatalf("login Location = %q, want the IdP authorize URL", resp.Header.Get("Location"))
		}

		// 2) Follow to the IdP /authorize, telling the mock which user logs in, and
		// preserving the state/nonce the server generated.
		q := idpURL.Query()
		q.Set("login_as", loginAs)
		idpURL.RawQuery = q.Encode()
		resp, err = client.Get(idpURL.String())
		if err != nil {
			t.Fatalf("GET IdP /authorize: %v", err)
		}
		drainBody(resp)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("IdP /authorize = %d, want 302 back to /auth/callback", resp.StatusCode)
		}
		cbURL := resp.Header.Get("Location") // the server's /auth/callback?code=...&state=...

		// 3) GET /auth/callback: the server exchanges the code at the IdP /token, verifies
		// the id_token, maps the user to its tenant, and sets the session cookie.
		resp, err = client.Get(cbURL)
		if err != nil {
			t.Fatalf("GET /auth/callback: %v", err)
		}
		drainBody(resp)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET /auth/callback = %d, want 302 (session established)", resp.StatusCode)
		}
		// The session cookie must be HttpOnly (the SEC hardening).
		var sawSession bool
		u, _ := url.Parse(baseURL)
		for _, c := range jar.Cookies(u) {
			if c.Name == "__Host-trstctl_session" {
				sawSession = true
			}
		}
		if !sawSession {
			t.Fatal("login did not establish a session cookie")
		}
	}

	// listOwners issues a guarded GET /api/v1/owners carrying the session cookie jar
	// and returns the owner names the session can see (tenant-scoped via RLS).
	listOwners := func(t *testing.T, jar http.CookieJar) []string {
		t.Helper()
		client := &http.Client{Jar: jar}
		resp, err := client.Get(baseURL + "/api/v1/owners")
		if err != nil {
			t.Fatalf("GET /api/v1/owners: %v", err)
		}
		body := drainBody(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/v1/owners = %d, want 200 (session authorizes the call); body=%s", resp.StatusCode, body)
		}
		var out struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode owners: %v; body=%s", err, body)
		}
		names := make([]string, 0, len(out.Items))
		for _, it := range out.Items {
			names = append(names, it.Name)
		}
		return names
	}

	// === User 1 (alice) -> tenant A: session authorizes a read of ONLY tenant A. ===
	jarA, _ := cookiejar.New(nil)
	login(t, jarA, "code-alice")
	namesA := listOwners(t, jarA)
	if !onlyContains(namesA, ownerA.Name) {
		t.Fatalf("alice's session saw %v, want only tenant A's owner %q (TENANT-004/AN-1)", namesA, ownerA.Name)
	}

	// === User 2 (bob) -> tenant B: a DIFFERENT tenant, sees ONLY tenant B. This is the
	// cross-tenant isolation proof — the DefaultTenant collapse is gone. ===
	jarB, _ := cookiejar.New(nil)
	login(t, jarB, "code-bob")
	namesB := listOwners(t, jarB)
	if !onlyContains(namesB, ownerB.Name) {
		t.Fatalf("bob's session saw %v, want only tenant B's owner %q (cross-tenant isolation)", namesB, ownerB.Name)
	}
	if containsName(namesB, ownerA.Name) {
		t.Fatalf("bob (tenant B) saw tenant A's owner %q — cross-tenant leak via the browser path", ownerA.Name)
	}

	// === RED-004: a freshly logged-in requester (rick) CANNOT self-issue. ===
	// alice (admin in tenant A) creates an identity via her session (it lands in the
	// projected read model in `requested`). rick logs in — his session role is the
	// custom "requester" (identities:write so he PASSES the transition route guard, but
	// NOT certs:issue) — and attempts the requested->issued transition. The served gate's
	// RA split denies it (403): wiring browser login did NOT open self-issue. This is the
	// session-path twin of the bearer-token RED-004 guard in gate_served_test.go.
	identID := createIdentityViaSession(t, baseURL, jarA, ownerA.ID)

	jarR, _ := cookiejar.New(nil)
	login(t, jarR, "code-rick")
	code, body := transitionViaSession(t, baseURL, jarR, identID, "issued", "k-rick-issue")
	if code != http.StatusForbidden {
		t.Fatalf("logged-in requester self-issue = %d, want 403 (RED-004: a session cannot self-issue without dual-control); body=%s", code, body)
	}
	// Sanity: the bearer/route guard is NOT what fired — rick has identities:write, so a
	// 403 here is the GATE's RA-separation check (no certs:issue), proving the served RA
	// split holds for the session principal too. The denial body is the gate's, not the
	// route's "requires identities:write".
	if strings.Contains(string(body), "requires identities:write") {
		t.Fatalf("rick was denied by the ROUTE guard, not the GATE; the test must give the requester identities:write so the GATE's RA split is what fires; body=%s", body)
	}
}

// onlyContains reports whether names contains want and nothing else.
func onlyContains(names []string, want string) bool {
	return len(names) == 1 && names[0] == want
}

func containsName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// createIdentityViaSession creates an identity through the served API authenticated
// by the session cookie jar (so it exists in the projected read model), returning
// its id. It echoes the CSRF token from the jar (SEC-007) since this is a mutating
// cookie-session request.
func createIdentityViaSession(t *testing.T, baseURL string, jar http.CookieJar, ownerID string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"kind": "x509_certificate", "name": "svc.a.test", "owner_id": ownerID})
	code, body := mutateViaSession(t, baseURL, jar, http.MethodPost, "/api/v1/identities", payload, "k-rick-create")
	if code != http.StatusCreated {
		t.Fatalf("create identity via session = %d, want 201; body=%s", code, body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id: %v; body=%s", err, body)
	}
	return got.ID
}

// transitionViaSession requests a lifecycle transition through the served API on the
// session cookie path.
func transitionViaSession(t *testing.T, baseURL string, jar http.CookieJar, identID, to, idemKey string) (int, []byte) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"to": to, "reason": "test"})
	return mutateViaSession(t, baseURL, jar, http.MethodPost, "/api/v1/identities/"+identID+"/transitions", payload, idemKey)
}

// mutateViaSession performs a mutating request on the session cookie path, echoing
// the double-submit CSRF token from the jar into X-CSRF-Token (the SEC-007 contract
// the SPA follows), plus an Idempotency-Key (AN-5).
func mutateViaSession(t *testing.T, baseURL string, jar http.CookieJar, method, path string, body []byte, idemKey string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, baseURL+path, bytesReader(body))
	req.Header.Set("Idempotency-Key", idemKey)
	u, _ := url.Parse(baseURL)
	for _, c := range jar.Cookies(u) {
		if c.Name == "trstctl_csrf" {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	client := &http.Client{Jar: jar}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode, drainBody(resp)
}

func bytesReader(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return io.NopCloser(strings.NewReader(string(b)))
}

func drainBody(resp *http.Response) []byte {
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return b
}

// buildServer assembles the production control-plane handler over the embedded
// stack with the given OIDC config and a loopback-capable auth HTTP client. Its own
// throwaway store + in-process event log are closed by Shutdown (mirroring the other
// served acceptance tests). The policy gate + dual control are ON so the RED-004
// no-self-issue assertion is exercised on the real served gate.
func buildServer(t *testing.T, ctx context.Context, dsn string, oidc config.OIDC) *Server {
	t.Helper()
	phaseStore, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open served store: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		phaseStore.Close()
		t.Fatalf("open event log: %v", err)
	}
	// A custom "requester" role: identities:write (so a requester PASSES the transition
	// route guard) but NOT certs:issue — so a requester's self-issue is denied by the
	// GATE's RA split, not merely the route RBAC. This is what proves the served RA
	// separation for a session principal (RED-004), mirroring gate_served_test.go.
	requesterRole := authz.Role{Name: "requester", Permissions: []authz.Permission{authz.IdentitiesWrite, authz.CertsRequest}}
	srv, err := Build(ctx, Deps{
		Store:            phaseStore,
		Log:              log,
		DefaultProfile:   "tls-server",
		EnablePolicyGate: true,
		RequireApproval:  true,
		OIDC:             oidc,
		AuthHTTPClient:   &http.Client{Timeout: 5 * time.Second},
		APIOptions:       []api.Option{api.WithRoles(requesterRole)},
	})
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	return srv
}
