// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedBrowserSignInIsRecordedPerPersonM1L2 is M1-L2's Done-when
// (served, the OIDC login through a stand-in IdP): a person's browser sign-in
// is recorded as a use of their sign-in — kind browser_session, action
// sign_in, from the client's network — under the tenant-bound subject
// reference, never the subject, in the event's opaque credential id; the
// members list shows each member's last sign-in and its network, and none for
// a member who never signed in; NHI usage posture lists no person's sign-in.
func TestServedBrowserSignInIsRecordedPerPersonM1L2(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenant   = "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"
		clientID = "trstctl-ui"
	)
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resetServerTestStore(t, st)
	idp := newMockIdP(t, clientID)
	idp.registerUser("code-dana", "dana-m1l2", map[string]any{"email": "dana@m1l2.test", "tenant": tenant})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	srv := buildServer(t, ctx, dsn, config.OIDC{
		Enabled: true, Issuer: idp.issuer, ClientID: clientID, AuthEndpoint: idp.issuer + "/authorize", TokenEndpoint: idp.issuer + "/token",
		RedirectURI: baseURL + "/auth/callback", JWKSJSON: idp.jwksJSON(t), SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h",
		TenantClaim: "tenant", ClaimIsTenant: true,
		TenantMappings: []config.TenantMapping{{Subject: "dana-m1l2", TenantID: tenant, Roles: []string{"admin"}}},
	})
	registerServerTestTenant(t, srv.store, srv.log, tenant, "M1-L2 tenant")
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	signIn := func() {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(baseURL + "/auth/login")
		if err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("GET /auth/login = %v %v", resp, err)
		}
		drainBody(resp)
		idpURL, _ := url.Parse(resp.Header.Get("Location"))
		q := idpURL.Query()
		q.Set("login_as", "code-dana")
		idpURL.RawQuery = q.Encode()
		if resp, err = client.Get(idpURL.String()); err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("IdP authorize = %v %v", resp, err)
		}
		drainBody(resp)
		if resp, err = client.Get(resp.Header.Get("Location")); err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("callback = %v %v", resp, err)
		}
		drainBody(resp)
	}

	admin := seedScopedTokenSubject(t, srv.store, tenant, "m1l2-admin", "*")
	call := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, baseURL+path, strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		if method != http.MethodGet {
			req.Header.Set("Idempotency-Key", "m1l2-"+strings.ReplaceAll(path, "/", "-"))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, drainBody(resp)
	}
	for _, subject := range []string{"dana-m1l2", "erin-m1l2"} {
		if code, body := call(http.MethodPut, "/api/v1/access/members/"+subject, map[string]any{"display_name": subject, "roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
			t.Fatalf("member %s = %d %s", subject, code, body)
		}
	}

	before, err := srv.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signIn()
	signIn()
	if err := srv.DrainCredentialUsage(ctx); err != nil {
		t.Fatal(err)
	}
	ref := privacy.SubjectRef(tenant, "dana-m1l2")
	var uses []projections.CredentialUsed
	if err := srv.log.Replay(ctx, before+1, func(e events.Event) error {
		if e.TenantID != tenant || e.Type != projections.EventCredentialUsed {
			return nil
		}
		var pl projections.CredentialUsed
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			return err
		}
		uses = append(uses, pl)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	signIns := 0
	for _, u := range uses {
		if u.Kind != store.CredentialUsageBrowserSession {
			continue
		}
		signIns++
		if u.CredentialID != ref || u.CredentialID == "dana-m1l2" || u.Principal != "dana-m1l2" || u.Action != projections.CredentialActionSignIn ||
			u.SourceKind != store.CredentialUsageSourceNetwork || u.Source != "127.0.0.0/24" {
			t.Fatalf("a browser sign-in was recorded as %+v; want the subject reference %s, sign_in from 127.0.0.0/24", u, ref)
		}
	}
	if signIns != 2 {
		t.Fatalf("two sign-ins in one hour recorded %d uses (the first and the doubling count), want 2", signIns)
	}

	code, body := call(http.MethodGet, "/api/v1/access/members", nil)
	var members struct {
		Items []struct {
			Subject           string     `json:"subject"`
			LastSignInAt      *time.Time `json:"last_sign_in_at"`
			LastSignInNetwork string     `json:"last_sign_in_network"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &members) != nil {
		t.Fatalf("members = %d %s", code, body)
	}
	seen := map[string]bool{}
	for _, m := range members.Items {
		switch m.Subject {
		case "dana-m1l2":
			seen[m.Subject] = true
			if m.LastSignInAt == nil || time.Since(*m.LastSignInAt) > time.Minute || m.LastSignInNetwork != "127.0.0.0/24" {
				t.Fatalf("dana's last sign-in reads %v from %q", m.LastSignInAt, m.LastSignInNetwork)
			}
		case "erin-m1l2":
			seen[m.Subject] = true
			if m.LastSignInAt != nil || m.LastSignInNetwork != "" {
				t.Fatalf("erin never signed in but reads %v from %q", m.LastSignInAt, m.LastSignInNetwork)
			}
		}
	}
	if !seen["dana-m1l2"] || !seen["erin-m1l2"] {
		t.Fatalf("the members list lacks the seeded members: %s", body)
	}

	code, body = call(http.MethodGet, "/api/v1/nhi/posture/stale?unused_days=1", nil)
	if code != http.StatusOK || strings.Contains(string(body), ref) || strings.Contains(string(body), "browser_session") || strings.Contains(string(body), "dana-m1l2") {
		t.Fatalf("NHI posture reads a person's sign-in: %d %s", code, body)
	}
	t.Logf("M1L2_OK subject_ref=%s sign_ins=%d", ref, signIns)
}
