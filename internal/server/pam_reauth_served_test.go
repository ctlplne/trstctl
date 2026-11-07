// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// TestServedHighRiskSessionNeedsAFreshSignInA277 is A277 part 2's Done-when:
// a session through a high-risk access template does not start without a
// fresh sign-in through the sign-in integration. The opener signed in to the
// console through OIDC two hours ago (the provider's own session); the
// approved activation is refused with an RFC 9470 step-up challenge, from the
// browser session and from the opener's API token alike, and nothing starts.
// A re-authentication asks the provider for prompt=login and max_age=0; a
// provider that reuses its session (an old auth_time) mints no session, and
// the activation is still refused. After the provider signs the person in
// again, the same activation, with the same idempotency key the console uses,
// starts the session on its unconsumed approval.
func TestServedHighRiskSessionNeedsAFreshSignInA277(t *testing.T) {
	const clientID = "trstctl-ui"
	idp := newMockIdP(t, clientID)
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, MaxTTL: 10 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.OIDC = config.OIDC{
			Enabled: true, Issuer: idp.issuer, ClientID: clientID,
			AuthEndpoint: idp.issuer + "/authorize", TokenEndpoint: idp.issuer + "/token",
			// The provider sends the browser back to this address; the test
			// follows it to the served handler.
			RedirectURI: "http://127.0.0.1:1/auth/callback", JWKSJSON: idp.jwksJSON(t),
			SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h",
			TenantClaim: "tenant", ClaimIsTenant: true, DefaultRoles: []string{"operator"},
		}
	})
	startServedExternalCADispatcher(t, h)
	served, _ := url.Parse(h.ts.URL)
	idp.registerUser("code-stale", "a277-opener", map[string]any{"tenant": h.tenant, "auth_time": time.Now().Add(-2 * time.Hour).Unix()})

	// signIn walks /auth/login -> provider -> /auth/callback in the jar and
	// returns the callback's response and what trstctl asked the provider.
	signIn := func(jar http.CookieJar, code string, reauth bool) (int, []byte, url.Values) {
		t.Helper()
		client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		path := "/auth/login"
		if reauth {
			path += "?reauth=1"
		}
		resp, err := client.Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		drainBody(resp)
		toIdP, err := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(toIdP.String(), idp.issuer+"/authorize") {
			t.Fatalf("GET %s = %d %q, want a redirect to the provider", path, resp.StatusCode, resp.Header.Get("Location"))
		}
		asked := toIdP.Query()
		q := toIdP.Query()
		q.Set("login_as", code)
		toIdP.RawQuery = q.Encode()
		resp, err = client.Get(toIdP.String())
		if err != nil {
			t.Fatal(err)
		}
		drainBody(resp)
		back, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		back.Scheme, back.Host = served.Scheme, served.Host
		resp, err = client.Get(back.String())
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, drainBody(resp), asked
	}
	// viaSession is one mutation on the browser session, with its CSRF echo.
	viaSession := func(jar http.CookieJar, path, key string, body any) (int, http.Header, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		for _, c := range jar.Cookies(served) {
			if c.Name == "trstctl_csrf" {
				req.Header.Set("X-CSRF-Token", c.Value)
			}
		}
		resp, err := (&http.Client{Jar: jar}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, out
	}
	stepUp := func(what string, status int, header http.Header, body []byte) {
		t.Helper()
		challenge := header.Get("WWW-Authenticate")
		if status != http.StatusUnauthorized || !strings.Contains(challenge, `error="insufficient_user_authentication"`) ||
			!strings.Contains(challenge, `max_age="300"`) || !strings.Contains(string(body), "insufficient_user_authentication") {
			t.Fatalf("%s = %d %q %s, want 401 with the step-up challenge (max_age 300)", what, status, challenge, body)
		}
	}

	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a277-admin", "access:read", "access:write", "access:targets.write")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a277-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a277-reviewer-2", "access:read", "access:approve"),
	}
	openerToken := seedScopedTokenSubject(t, h.store, h.tenant, "a277-opener", "access:read", "access:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", admin, "a277r-register",
		map[string]any{"id": "orders-pg", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}}); status != http.StatusCreated {
		t.Fatalf("register: %d %s", status, body)
	}
	template := map[string]any{"name": "prod-dba", "reason": "production database change", "required_approvals": 2, "max_ttl_seconds": 300,
		"reauthenticate_within_seconds": 30}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/templates", admin, "a277r-template-short", template); status != http.StatusUnprocessableEntity {
		t.Fatalf("a 30-second window = %d %s, want 422", status, body)
	}
	template["reauthenticate_within_seconds"] = 300
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/templates", admin, "a277r-template", template)
	var saved struct {
		ID                          string `json:"id"`
		ReauthenticateWithinSeconds int    `json:"reauthenticate_within_seconds"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &saved) != nil || saved.ReauthenticateWithinSeconds != 300 {
		t.Fatalf("high-risk template: %d %s", status, body)
	}

	// The opener signed in through the provider's two-hour-old session.
	jar, _ := cookiejar.New(nil)
	if status, body, _ := signIn(jar, "code-stale", false); status != http.StatusFound {
		t.Fatalf("console sign-in: %d %s", status, body)
	}
	session := map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-pg", "role": "readonly",
		"reason": "CHG-277 fix the orders ledger", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ttl_seconds": 60, "template_id": saved.ID}
	status, _, body = viaSession(jar, "/api/v1/access/session-requests", "a277r-request", session)
	var pending api.PAMApprovalRequest
	if status != http.StatusAccepted || json.Unmarshal(body, &pending) != nil || pending.ApprovalRequestID == "" {
		t.Fatalf("request through the template: %d %s", status, body)
	}
	for i, reviewer := range reviewers {
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewer,
			"a277r-review-"+string(rune('1'+i)), map[string]any{"intent_digest": pending.IntentDigest}); status != http.StatusOK {
			t.Fatalf("review %d: %d %s", i+1, status, body)
		}
	}
	session["approval_request_id"], session["intent_digest"] = pending.ApprovalRequestID, pending.IntentDigest
	activationKey := "pam-activate:" + session["request_id"].(string)

	// Approved, but the sign-in is two hours old: refused, nothing starts.
	status, header, body := viaSession(jar, "/api/v1/access/sessions", activationKey, session)
	stepUp("activation on the two-hour-old sign-in", status, header, body)
	// An API token cannot prove a sign-in at all.
	tokenStatus, tokenBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", openerToken, "a277r-open-token", session)
	if tokenStatus != http.StatusUnauthorized || !strings.Contains(string(tokenBody), "insufficient_user_authentication") {
		t.Fatalf("activation with the opener's API token = %d %s, want 401", tokenStatus, tokenBody)
	}
	noSessions := func(what string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/sessions", admin, nil)
		var listed struct {
			Items []json.RawMessage `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 0 {
			t.Fatalf("%s started a session: %d %s", what, status, body)
		}
	}
	noSessions("a refused activation")

	// A re-authentication asks for a fresh sign-in. A provider that reuses
	// its session instead mints no session, and the activation stays refused.
	status, body, asked := signIn(jar, "code-stale", true)
	if asked.Get("prompt") != "login" || asked.Get("max_age") != "0" {
		t.Fatalf("the re-authentication asked the provider for %v, want prompt=login and max_age=0", asked)
	}
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "did not sign you in again") {
		t.Fatalf("a re-authentication the provider did not perform = %d %s, want 401", status, body)
	}
	status, header, body = viaSession(jar, "/api/v1/access/sessions", activationKey, session)
	stepUp("activation after the provider reused its session", status, header, body)
	noSessions("an unproven re-authentication")

	// The provider signs the person in again: the session starts.
	idp.registerUser("code-fresh", "a277-opener", map[string]any{"tenant": h.tenant, "auth_time": time.Now().Unix()})
	if status, body, _ := signIn(jar, "code-fresh", true); status != http.StatusFound {
		t.Fatalf("fresh sign-in: %d %s", status, body)
	}
	status, _, body = viaSession(jar, "/api/v1/access/sessions", activationKey, session)
	var opened servedPAMSessionResponse
	if status != http.StatusCreated || json.Unmarshal(body, &opened) != nil || opened.Status != "active" || opened.Postgres == nil {
		t.Fatalf("activation after the fresh sign-in = %d %s, want the session active", status, body)
	}
}
