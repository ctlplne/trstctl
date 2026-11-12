// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSAMLFreshSignInIsProvenByTheAssertionA277O1 is A277-O1: a SAML
// sign-in is as fresh as the IdP's authentication of the person, from the
// assertion's AuthnInstant. An ordinary sign-in that reuses an IdP session two
// hours old records that instant. A fresh sign-in (reauth=1) asks the IdP for
// ForceAuthn; an IdP that authenticates the person again yields a session
// signed in now, and one that answers from its old session is refused, with
// no session minted.
func TestServedSAMLFreshSignInIsProvenByTheAssertionA277O1(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantA = "11111111-1111-1111-1111-111111111111"
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()
	idp := newMockSAMLIdP(t)
	samlCfg := config.SAML{
		Enabled: true, EntityID: baseURL + "/auth/saml/metadata", MetadataURL: baseURL + "/auth/saml/metadata", ACSURL: baseURL + "/auth/saml/acs",
		IDPMetadataXML: idp.metadataXML(t), SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h", LoginRedirect: "/",
		TenantClaim: "tenant", GroupsClaim: "groups", EmailAttribute: "email",
		TenantMappings: []config.TenantMapping{{Subject: "alice@example.test", TenantID: tenantA, Roles: []string{"admin"}}},
	}
	idp.spEntityID, idp.spMetadataURL = samlCfg.EntityID, samlCfg.MetadataURL
	idp.registerUser("alice", "alice@example.test", "alice@example.test", tenantA, []string{"admins"})
	// The IdP authenticated alice two hours ago and keeps that session.
	idp.users["alice"].CreateTime = time.Now().Add(-2 * time.Hour)
	idp.nextUser = "alice"
	srv := buildSAMLServer(t, ctx, dsn, samlCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	// signIn runs an SP-initiated sign-in and returns the ACS's answer.
	signIn := func(jar http.CookieJar, query string) (int, []byte) {
		t.Helper()
		client := noFollowClient(jar)
		resp, err := client.Get(baseURL + "/auth/saml/login" + query)
		if err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("GET /auth/saml/login%s = %v %v", query, resp, err)
		}
		_ = resp.Body.Close()
		resp, err = client.Get(resp.Header.Get("Location"))
		if err != nil {
			t.Fatalf("GET IdP SSO: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("IdP SSO = %d: %s", resp.StatusCode, body)
		}
		form := url.Values{"SAMLResponse": {samlHiddenInput(t, body, "SAMLResponse")}}
		if relay := samlHiddenInput(t, body, "RelayState"); relay != "" {
			form.Set("RelayState", relay)
		}
		resp, err = client.PostForm(samlFormAction(t, body), form)
		if err != nil {
			t.Fatalf("POST SAML ACS: %v", err)
		}
		answer, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, answer
	}
	signedInAt := func(jar http.CookieJar) (time.Time, int) {
		t.Helper()
		resp, err := (&http.Client{Jar: jar}).Get(baseURL + "/auth/me")
		if err != nil {
			t.Fatalf("GET /auth/me: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var me struct {
			SignedInAt *time.Time `json:"signed_in_at"`
		}
		if resp.StatusCode != http.StatusOK {
			return time.Time{}, resp.StatusCode
		}
		if err := json.NewDecoder(resp.Body).Decode(&me); err != nil || me.SignedInAt == nil {
			t.Fatalf("/auth/me has no sign-in time: %v", err)
		}
		return *me.SignedInAt, resp.StatusCode
	}

	ordinary, _ := cookiejar.New(nil)
	if status, body := signIn(ordinary, ""); status != http.StatusFound {
		t.Fatalf("an ordinary SAML sign-in = %d %s", status, body)
	}
	if at, _ := signedInAt(ordinary); time.Since(at) < 110*time.Minute || idp.forceAuthnSeen != 0 {
		t.Fatalf("an ordinary sign-in on a two-hour IdP session recorded %s (ForceAuthn asked %d times)", at, idp.forceAuthnSeen)
	}

	idp.honorForceAuthn = true
	fresh, _ := cookiejar.New(nil)
	if status, body := signIn(fresh, "?reauth=1"); status != http.StatusFound {
		t.Fatalf("a fresh SAML sign-in = %d %s", status, body)
	}
	if at, _ := signedInAt(fresh); time.Since(at) > time.Minute || idp.forceAuthnSeen != 1 {
		t.Fatalf("a fresh sign-in recorded %s (ForceAuthn asked %d times)", at, idp.forceAuthnSeen)
	}

	idp.honorForceAuthn = false
	reused, _ := cookiejar.New(nil)
	status, body := signIn(reused, "?reauth=1")
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "insufficient_user_authentication") || idp.forceAuthnSeen != 2 {
		t.Fatalf("a fresh sign-in the IdP answered from its old session = %d %s (ForceAuthn asked %d times)", status, body, idp.forceAuthnSeen)
	}
	if _, status := signedInAt(reused); status != http.StatusUnauthorized {
		t.Fatalf("a refused fresh sign-in minted a session: /auth/me = %d", status)
	}
}
