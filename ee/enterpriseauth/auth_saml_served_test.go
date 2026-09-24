// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/xml"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/crewjam/saml"
	crewjamsamlsp "github.com/crewjam/saml/samlsp"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/samltest"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSAMLLoginEndToEndSPAndIDPInitiated is the IAM-02 acceptance test:
// the served binary must expose a real SAML 2.0 Service Provider, accept both
// SP-initiated and IdP-initiated signed POST-binding assertions from a mock IdP,
// and mint the same tenant-scoped browser session the OIDC path uses.
func TestServedSAMLLoginEndToEndSPAndIDPInitiated(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + ln.Addr().String()

	idp := newMockSAMLIdP(t)
	samlCfg := config.SAML{
		Enabled:           true,
		EntityID:          baseURL + "/auth/saml/metadata",
		MetadataURL:       baseURL + "/auth/saml/metadata",
		ACSURL:            baseURL + "/auth/saml/acs",
		IDPMetadataXML:    idp.metadataXML(t),
		SessionSecretFile: t.TempDir() + "/session.secret",
		SessionTTL:        "1h",
		LoginRedirect:     "/",
		TenantClaim:       "tenant",
		GroupsClaim:       "groups",
		EmailAttribute:    "email",
		TenantMappings: []config.TenantMapping{
			{Subject: "alice@example.test", TenantID: tenantA, Roles: []string{"admin"}},
			{Subject: "bob@example.test", TenantID: tenantB, Roles: []string{"admin"}},
		},
	}
	idp.spEntityID = samlCfg.EntityID
	idp.spMetadataURL = samlCfg.MetadataURL
	idp.registerUser("alice", "alice@example.test", "alice@example.test", tenantA, []string{"admins"})
	idp.registerUser("bob", "bob@example.test", "bob@example.test", tenantB, []string{"admins"})

	srv := buildSAMLServer(t, ctx, dsn, samlCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	jarA, _ := cookiejar.New(nil)
	idp.nextUser = "alice"
	assertSAMLSPInitiatedSession(t, baseURL, jarA, tenantA)

	jarB, _ := cookiejar.New(nil)
	idp.nextUser = "bob"
	assertSAMLIDPInitiatedSession(t, baseURL, idp, jarB, tenantB)
}

func assertSAMLSPInitiatedSession(t *testing.T, baseURL string, jar http.CookieJar, wantTenant string) {
	t.Helper()
	client := noFollowClient(jar)
	const target = "/certificates?expiry=30d&owner=a%20b#inventory"
	resp, err := client.Get(baseURL + "/auth/saml/login?return_to=" + url.QueryEscape(target))
	if err != nil {
		t.Fatalf("GET /auth/saml/login: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/saml/login = %d, want 302 to IdP", resp.StatusCode)
	}
	idpURL := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if idpURL == "" {
		t.Fatal("SAML login returned no IdP Location")
	}

	resp, err = client.Get(idpURL)
	if err != nil {
		t.Fatalf("GET IdP SSO: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP SSO = %d, want HTML POST form: %s", resp.StatusCode, body)
	}
	if got := postSAMLForm(t, client, body); got != target {
		t.Fatalf("signed SAML callback destination = %q, want %q", got, target)
	}
	assertAuthMeTenant(t, baseURL, jar, wantTenant)
}

func assertSAMLIDPInitiatedSession(t *testing.T, baseURL string, idp *mockSAMLIdP, jar http.CookieJar, wantTenant string) {
	t.Helper()
	client := noFollowClient(jar)
	resp, err := client.Get(idp.srv.URL + "/idp-init")
	if err != nil {
		t.Fatalf("GET IdP-initiated login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP-initiated login = %d, want HTML POST form: %s", resp.StatusCode, body)
	}
	if got := postSAMLForm(t, client, body); got != "/" {
		t.Fatalf("IdP-initiated callback destination = %q, want configured home", got)
	}
	assertAuthMeTenant(t, baseURL, jar, wantTenant)
}

func postSAMLForm(t *testing.T, client *http.Client, body []byte) string {
	t.Helper()
	action := samlFormAction(t, body)
	form := url.Values{}
	form.Set("SAMLResponse", samlHiddenInput(t, body, "SAMLResponse"))
	if relay := samlHiddenInput(t, body, "RelayState"); relay != "" {
		form.Set("RelayState", relay)
	}
	resp, err := client.PostForm(action, form)
	if err != nil {
		t.Fatalf("POST SAML ACS: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST SAML ACS = %d, want 302 session redirect: %s", resp.StatusCode, respBody)
	}
	return resp.Header.Get("Location")
}

func assertAuthMeTenant(t *testing.T, baseURL string, jar http.CookieJar, wantTenant string) {
	t.Helper()
	resp, err := (&http.Client{Jar: jar}).Get(baseURL + "/auth/me")
	if err != nil {
		t.Fatalf("GET /auth/me: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me = %d, want 200: %s", resp.StatusCode, body)
	}
	if got := string(body); !regexp.MustCompile(`"tenant_id"\s*:\s*"` + regexp.QuoteMeta(wantTenant) + `"`).MatchString(got) {
		t.Fatalf("/auth/me tenant mismatch, want %s: %s", wantTenant, got)
	}
}

func noFollowClient(jar http.CookieJar) *http.Client {
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func samlFormAction(t *testing.T, body []byte) string {
	t.Helper()
	m := regexp.MustCompile(`<form[^>]+action="([^"]+)"`).FindSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("SAML form missing action: %s", body)
	}
	return html.UnescapeString(string(m[1]))
}

func samlHiddenInput(t *testing.T, body []byte, name string) string {
	t.Helper()
	m := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`).FindSubmatch(body)
	if len(m) != 2 {
		return ""
	}
	return html.UnescapeString(string(m[1]))
}

type mockSAMLIdP struct {
	srv           *httptest.Server
	idp           *saml.IdentityProvider
	users         map[string]*saml.Session
	nextUser      string
	spEntityID    string
	spMetadataURL string
}

func newMockSAMLIdP(t *testing.T) *mockSAMLIdP {
	t.Helper()
	key, cert, err := samltest.NewIdentityProviderMaterial("trstctl-test-idp")
	if err != nil {
		t.Fatalf("generate SAML IdP material: %v", err)
	}
	m := &mockSAMLIdP{users: map[string]*saml.Session{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata":
			m.idp.ServeMetadata(w, r)
		case "/sso":
			m.idp.ServeSSO(w, r)
		case "/idp-init":
			m.idp.ServeIDPInitiated(w, r, m.spEntityID, "")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	metadataURL := mustParseSAMLURL(t, m.srv.URL+"/metadata")
	ssoURL := mustParseSAMLURL(t, m.srv.URL+"/sso")
	m.idp = &saml.IdentityProvider{
		Certificate:             cert,
		Key:                     key,
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		ServiceProviderProvider: m,
		SessionProvider:         m,
	}
	return m
}

func (m *mockSAMLIdP) registerUser(key, nameID, email, tenant string, groups []string) {
	now := time.Now()
	m.users[key] = &saml.Session{
		ID:         key,
		CreateTime: now,
		ExpireTime: now.Add(time.Hour),
		Index:      key + "-session",
		NameID:     nameID,
		UserEmail:  email,
		Groups:     groups,
		CustomAttributes: []saml.Attribute{
			{Name: "email", FriendlyName: "email", Values: []saml.AttributeValue{{Type: "xs:string", Value: email}}},
			{Name: "tenant", FriendlyName: "tenant", Values: []saml.AttributeValue{{Type: "xs:string", Value: tenant}}},
			{Name: "groups", FriendlyName: "groups", Values: samlAttributeValues(groups)},
		},
	}
}

func samlAttributeValues(values []string) []saml.AttributeValue {
	out := make([]saml.AttributeValue, 0, len(values))
	for _, v := range values {
		out = append(out, saml.AttributeValue{Type: "xs:string", Value: v})
	}
	return out
}

func (m *mockSAMLIdP) metadataXML(t *testing.T) string {
	t.Helper()
	data, err := xml.MarshalIndent(m.idp.Metadata(), "", "  ")
	if err != nil {
		t.Fatalf("marshal IdP metadata: %v", err)
	}
	return string(data)
}

func (m *mockSAMLIdP) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	if m.nextUser == "" {
		return nil
	}
	return m.users[m.nextUser]
}

func (m *mockSAMLIdP) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	if serviceProviderID != m.spEntityID {
		return nil, os.ErrNotExist
	}
	resp, err := http.Get(m.spMetadataURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, os.ErrNotExist
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return crewjamsamlsp.ParseMetadata(body)
}

func mustParseSAMLURL(t *testing.T, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse SAML URL %q: %v", raw, err)
	}
	return *u
}

func buildSAMLServer(t *testing.T, ctx context.Context, dsn string, samlCfg config.SAML) *server.Server {
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
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: phaseStore, Log: log, SAML: samlCfg})
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	return srv
}
