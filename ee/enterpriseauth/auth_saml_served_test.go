// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	crewjamsamlsp "github.com/crewjam/saml/samlsp"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/samltest"
	"trstctl.com/trstctl/internal/crypto/seal"
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
	// artifacts holds signed Response documents issued under the HTTP-Artifact
	// binding (A76), keyed by the opaque artifact the browser carried.
	artifacts map[string][]byte
	resolves  int
	key       any
	cert      any
	// logoutRequests counts the SP-initiated LogoutRequests the IdP consumed
	// (A78); lastLogoutNameID is the NameID the last one named.
	logoutRequests   int
	lastLogoutNameID string
}

// serveSLO is the IdP's single logout service (A78): it consumes the SP's
// redirect-binding LogoutRequest and answers with a signed LogoutResponse
// redirect to the SP's SLO URL, as a real IdP would.
func (m *mockSAMLIdP) serveSLO(w http.ResponseWriter, r *http.Request) {
	raw, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
	if err != nil {
		http.Error(w, "bad SAMLRequest", http.StatusBadRequest)
		return
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		http.Error(w, "bad SAMLRequest", http.StatusBadRequest)
		return
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(inflated, &req); err != nil || req.NameID == nil {
		http.Error(w, "bad LogoutRequest", http.StatusBadRequest)
		return
	}
	m.logoutRequests++
	m.lastLogoutNameID = req.NameID.Value
	sloURL := m.spSLOURL()
	resp := saml.LogoutResponse{ID: fmt.Sprintf("id-idp-logout-response-%d", m.logoutRequests), InResponseTo: req.ID, Version: "2.0",
		IssueInstant: time.Now().UTC(), Destination: sloURL, Issuer: &saml.Issuer{Value: m.idp.Metadata().EntityID},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}}
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	unsigned, err := doc.WriteToBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signed, err := samltest.SignEnvelopedXML(m.key, m.cert, unsigned)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The redirect binding carries DEFLATE-compressed, base64-encoded XML.
	var deflated bytes.Buffer
	compressor, err := flate.NewWriter(&deflated, flate.BestCompression)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := compressor.Write(signed); err != nil || compressor.Close() != nil {
		http.Error(w, "deflate", http.StatusInternalServerError)
		return
	}
	query := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(deflated.Bytes())}}
	if rs := r.URL.Query().Get("RelayState"); rs != "" {
		query.Set("RelayState", rs)
	}
	http.Redirect(w, r, sloURL+"?"+query.Encode(), http.StatusFound) // #nosec G710 -- test IdP redirects to the SP's own SLO URL read from its metadata (CWE-601)
}

// spSLOURL reads the SP's SingleLogoutService location from its live metadata.
func (m *mockSAMLIdP) spSLOURL() string {
	descriptor, err := m.GetServiceProvider(nil, m.spEntityID)
	if err != nil {
		return ""
	}
	for _, sp := range descriptor.SPSSODescriptors {
		for _, slo := range sp.SingleLogoutServices {
			return slo.Location
		}
	}
	return ""
}

// idpInitiatedLogoutForm builds the signed LogoutRequest a real IdP posts to
// the SP's SLO URL when the user signs out elsewhere (A78).
func (m *mockSAMLIdP) idpInitiatedLogoutForm(t *testing.T, nameID string) (string, url.Values) {
	t.Helper()
	sloURL := m.spSLOURL()
	req := saml.LogoutRequest{ID: "id-idp-initiated-logout-1", Version: "2.0", IssueInstant: time.Now().UTC(), Destination: sloURL,
		Issuer: &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: m.idp.Metadata().EntityID},
		NameID: &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: nameID}}
	raw, err := req.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := samltest.SignEnvelopedXML(m.key, m.cert, raw)
	if err != nil {
		t.Fatal(err)
	}
	return sloURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(signed)}, "RelayState": {"idp-rs"}}
}

// serveSSO answers an AuthnRequest the way the IdP library does for the POST
// binding, and for the artifact binding hands the browser only an opaque
// artifact while keeping the signed Response for the back-channel.
func (m *mockSAMLIdP) serveSSO(w http.ResponseWriter, r *http.Request) {
	req, err := saml.NewIdpAuthnRequest(m.idp, r)
	if err != nil || req.Validate() != nil {
		http.Error(w, "bad AuthnRequest", http.StatusBadRequest)
		return
	}
	if req.Request.ProtocolBinding != saml.HTTPArtifactBinding {
		m.idp.ServeSSO(w, r)
		return
	}
	session := m.users[m.nextUser]
	if session == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := req.MakeResponse(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	form, err := req.PostBinding()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(form.SAMLResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if m.artifacts == nil {
		m.artifacts = map[string][]byte{}
	}
	artifact := fmt.Sprintf("AAQAA-mock-artifact-%d", len(m.artifacts)+1)
	m.artifacts[artifact] = raw
	query := url.Values{"SAMLart": {artifact}}
	if req.RelayState != "" {
		query.Set("RelayState", req.RelayState)
	}
	http.Redirect(w, r, req.ACSEndpoint.Location+"?"+query.Encode(), http.StatusFound) // #nosec G710 -- test IdP redirects to the ACS it read from the SP's own metadata (CWE-601)
}

// serveArtifactResolve answers the SP's SOAP ArtifactResolve with an
// ArtifactResponse wrapping the signed Response issued for that artifact.
func (m *mockSAMLIdP) serveArtifactResolve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	resolveID := regexp.MustCompile(`ArtifactResolve[^>]*\sID="([^"]+)"`).FindSubmatch(body)
	artifact := regexp.MustCompile(`<(?:samlp:)?Artifact>([^<]+)</(?:samlp:)?Artifact>`).FindSubmatch(body)
	if r.Method != http.MethodPost || len(resolveID) != 2 || len(artifact) != 2 {
		http.Error(w, "bad ArtifactResolve", http.StatusBadRequest)
		return
	}
	response, ok := m.artifacts[string(artifact[1])]
	if !ok {
		http.Error(w, "unknown artifact", http.StatusNotFound)
		return
	}
	delete(m.artifacts, string(artifact[1]))
	m.resolves++
	w.Header().Set("Content-Type", "text/xml")
	_, _ = fmt.Fprintf(w, `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>`+
		`<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-artifact-response-%d" InResponseTo="%s" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:ArtifactResponse></soapenv:Body></soapenv:Envelope>`,
		m.resolves, html.EscapeString(string(resolveID[1])), time.Now().UTC().Format(time.RFC3339), html.EscapeString(m.idp.Metadata().EntityID), response)
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
			m.serveSSO(w, r)
		case "/artifact":
			m.serveArtifactResolve(w, r)
		case "/slo":
			m.serveSLO(w, r)
		case "/idp-init":
			m.idp.ServeIDPInitiated(w, r, m.spEntityID, "")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	metadataURL := mustParseSAMLURL(t, m.srv.URL+"/metadata")
	ssoURL := mustParseSAMLURL(t, m.srv.URL+"/sso")
	m.key, m.cert = key, cert
	m.idp = &saml.IdentityProvider{
		Certificate:             cert,
		Key:                     key,
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		LogoutURL:               mustParseSAMLURL(t, m.srv.URL+"/slo"),
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
	descriptor := m.idp.Metadata()
	// A76: declare the SOAP artifact resolution service beside SSO.
	descriptor.IDPSSODescriptors[0].ArtifactResolutionServices = []saml.Endpoint{{Binding: saml.SOAPBinding, Location: m.srv.URL + "/artifact"}}
	data, err := xml.MarshalIndent(descriptor, "", "  ")
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
	return buildSAMLServerWithDeps(t, ctx, dsn, samlCfg, nil)
}

func buildSAMLServerWithDeps(t *testing.T, ctx context.Context, dsn string, samlCfg config.SAML, mutate func(*server.Deps)) *server.Server {
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
	deps := server.Deps{TenantAuthFactory: Build, Store: phaseStore, Log: log, SAML: samlCfg}
	if mutate != nil {
		mutate(&deps)
	}
	srv, err := server.Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	return srv
}

// A76: with auth.saml.response_binding "artifact" the browser never carries the
// signed assertion. The SP asks for the HTTP-Artifact result binding, the IdP
// redirects the browser to the ACS with only an opaque SAMLart, and the served
// binary resolves it over a back-channel SOAP call before minting the same
// tenant session the POST binding mints.
func TestServedSAMLArtifactBindingLoginResolvesOverTheBackChannel(t *testing.T) {
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
		Enabled: true, EntityID: baseURL + "/auth/saml/metadata", MetadataURL: baseURL + "/auth/saml/metadata",
		ACSURL: baseURL + "/auth/saml/acs", IDPMetadataXML: idp.metadataXML(t), ResponseBinding: "artifact",
		SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h", LoginRedirect: "/",
		TenantClaim: "tenant", GroupsClaim: "groups", EmailAttribute: "email",
		TenantMappings: []config.TenantMapping{{Subject: "alice@example.test", TenantID: tenantA, Roles: []string{"admin"}}},
	}
	idp.spEntityID = samlCfg.EntityID
	idp.spMetadataURL = samlCfg.MetadataURL
	idp.registerUser("alice", "alice@example.test", "alice@example.test", tenantA, []string{"admins"})
	srv := buildSAMLServer(t, ctx, dsn, samlCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	jar, _ := cookiejar.New(nil)
	client := noFollowClient(jar)
	idp.nextUser = "alice"
	const target = "/certificates?expiry=30d"
	resp, err := client.Get(baseURL + "/auth/saml/login?return_to=" + url.QueryEscape(target))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/saml/login = %v %v, want 302 to the IdP", resp, err)
	}
	idpURL := resp.Header.Get("Location")
	_ = resp.Body.Close()
	resp, err = client.Get(idpURL)
	if err != nil {
		t.Fatalf("GET IdP SSO: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP SSO under the artifact binding = %d, want a 302 carrying SAMLart: %s", resp.StatusCode, body)
	}
	acs := resp.Header.Get("Location")
	if !strings.Contains(acs, "SAMLart=") || strings.Contains(acs, "SAMLResponse=") {
		t.Fatalf("IdP redirect = %q, want an opaque artifact and no assertion", acs)
	}
	resp, err = client.Get(acs)
	if err != nil {
		t.Fatalf("GET ACS with the artifact: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != target {
		t.Fatalf("ACS with the artifact = %d → %q (%s), want 302 to %q", resp.StatusCode, resp.Header.Get("Location"), body, target)
	}
	if idp.resolves != 1 {
		t.Fatalf("artifact resolutions = %d, want exactly one back-channel call", idp.resolves)
	}
	assertAuthMeTenant(t, baseURL, jar, tenantA)

	// The same artifact cannot be replayed: the IdP has consumed it and the
	// SP reports the failed resolution as a verification failure.
	resp, err = client.Get(acs)
	if err != nil {
		t.Fatalf("replayed ACS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed artifact = %d, want a refusal", resp.StatusCode)
	}
}

// A77: with auth.saml.sp_key_file the SP advertises an encryption certificate,
// the IdP (the library's, which honors an encryption KeyDescriptor) sends an
// EncryptedAssertion instead of a plaintext one, and the served binary
// decrypts it inside the cryptography boundary and mints the same session.
func TestServedSAMLEncryptedAssertionIsDecryptedBehindTheBoundary(t *testing.T) {
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
		Enabled: true, EntityID: baseURL + "/auth/saml/metadata", MetadataURL: baseURL + "/auth/saml/metadata",
		ACSURL: baseURL + "/auth/saml/acs", IDPMetadataXML: idp.metadataXML(t),
		SPKeyFile:         t.TempDir() + "/sp-encryption.sealed",
		SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h", LoginRedirect: "/",
		TenantClaim: "tenant", GroupsClaim: "groups", EmailAttribute: "email",
		TenantMappings: []config.TenantMapping{{Subject: "alice@example.test", TenantID: tenantA, Roles: []string{"admin"}}},
	}
	idp.spEntityID = samlCfg.EntityID
	idp.spMetadataURL = samlCfg.MetadataURL
	idp.registerUser("alice", "alice@example.test", "alice@example.test", tenantA, []string{"admins"})
	rawKEK, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(rawKEK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	srv := buildSAMLServerWithDeps(t, ctx, dsn, samlCfg, func(d *server.Deps) { d.KEK = kek })
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	resp, err := http.Get(baseURL + "/auth/saml/metadata")
	if err != nil {
		t.Fatalf("GET SP metadata: %v", err)
	}
	metadata, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(metadata), `use="encryption"`) {
		t.Fatalf("SP metadata advertises no encryption key: %s", metadata)
	}

	jar, _ := cookiejar.New(nil)
	client := noFollowClient(jar)
	idp.nextUser = "alice"
	resp, err = client.Get(baseURL + "/auth/saml/login")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/saml/login = %v %v", resp, err)
	}
	idpURL := resp.Header.Get("Location")
	_ = resp.Body.Close()
	resp, err = client.Get(idpURL)
	if err != nil {
		t.Fatalf("GET IdP SSO: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP SSO = %d: %s", resp.StatusCode, body)
	}
	wire, err := base64.StdEncoding.DecodeString(samlHiddenInput(t, body, "SAMLResponse"))
	if err != nil {
		t.Fatalf("decode the IdP response: %v", err)
	}
	if !strings.Contains(string(wire), "EncryptedAssertion") || strings.Contains(string(wire), "<saml:Assertion") {
		t.Fatalf("the IdP response on the wire is not an encrypted assertion: %s", wire)
	}
	if got := postSAMLForm(t, client, body); got != "/" {
		t.Fatalf("encrypted-assertion login landed on %q, want /", got)
	}
	assertAuthMeTenant(t, baseURL, jar, tenantA)
}

// A78: a sign-out from trstctl also ends the IdP session (SP-initiated single
// logout), and a LogoutRequest from the IdP ends the user's trstctl sessions
// (IdP-initiated), each answered the way the SAML profile expects.
func TestServedSAMLSingleLogoutPropagatesBothWays(t *testing.T) {
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
		Enabled: true, EntityID: baseURL + "/auth/saml/metadata", MetadataURL: baseURL + "/auth/saml/metadata",
		ACSURL: baseURL + "/auth/saml/acs", IDPMetadataXML: idp.metadataXML(t),
		SingleLogout: true, SLOURL: baseURL + "/auth/saml/slo",
		SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h", LoginRedirect: "/",
		TenantClaim: "tenant", GroupsClaim: "groups", EmailAttribute: "email",
		TenantMappings: []config.TenantMapping{{Subject: "alice@example.test", TenantID: tenantA, Roles: []string{"admin"}}},
	}
	idp.spEntityID = samlCfg.EntityID
	idp.spMetadataURL = samlCfg.MetadataURL
	idp.registerUser("alice", "alice@example.test", "alice@example.test", tenantA, []string{"admins"})
	srv := buildSAMLServer(t, ctx, dsn, samlCfg)
	defer func() { _ = srv.Shutdown(context.Background()) }()
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	resp, err := http.Get(baseURL + "/auth/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(metadata), "SingleLogoutService") {
		t.Fatalf("SP metadata declares no SingleLogoutService: %s", metadata)
	}

	// SP-initiated: sign in, sign out, follow the IdP logout, land on the SP.
	jar, _ := cookiejar.New(nil)
	idp.nextUser = "alice"
	assertSAMLSPInitiatedSession(t, baseURL, jar, tenantA)
	client := noFollowClient(jar)
	logoutReq, _ := http.NewRequest(http.MethodPost, baseURL+"/auth/logout", nil)
	logoutReq.Header.Set("X-CSRF-Token", csrfCookieValue(t, jar, baseURL))
	resp, err = client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /auth/logout: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var logout struct {
		LogoutURL string `json:"logout_url"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &logout) != nil || !strings.HasPrefix(logout.LogoutURL, idp.srv.URL+"/slo?") {
		t.Fatalf("POST /auth/logout for a SAML session = %d %s, want 200 with the IdP logout_url", resp.StatusCode, body)
	}
	assertAuthMeUnauthorized(t, baseURL, jar)
	resp, err = client.Get(logout.LogoutURL)
	if err != nil {
		t.Fatalf("GET IdP SLO: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || idp.logoutRequests != 1 || idp.lastLogoutNameID != "alice@example.test" {
		t.Fatalf("IdP SLO = %d (requests %d, nameID %q), want the SP's LogoutRequest consumed", resp.StatusCode, idp.logoutRequests, idp.lastLogoutNameID)
	}
	back := resp.Header.Get("Location")
	resp, err = client.Get(back)
	if err != nil {
		t.Fatalf("GET SP SLO with the LogoutResponse: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("SP SLO with the IdP's LogoutResponse = %d → %q, want 302 to the login page", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A LogoutResponse replayed to a browser that started no sign-out is refused.
	fresh, _ := cookiejar.New(nil)
	resp, err = noFollowClient(fresh).Get(back)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed LogoutResponse without the browser's logout context = %d, want 400", resp.StatusCode)
	}

	// IdP-initiated: a live session ends when the IdP posts a LogoutRequest.
	jar2, _ := cookiejar.New(nil)
	idp.nextUser = "alice"
	assertSAMLSPInitiatedSession(t, baseURL, jar2, tenantA)
	sloURL, form := idp.idpInitiatedLogoutForm(t, "alice@example.test")
	resp, err = noFollowClient(nil).PostForm(sloURL, form)
	if err != nil {
		t.Fatalf("POST IdP-initiated LogoutRequest: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), idp.srv.URL+"/slo?") || !strings.Contains(resp.Header.Get("Location"), "SAMLResponse=") {
		t.Fatalf("IdP-initiated logout = %d → %q, want a LogoutResponse redirect to the IdP", resp.StatusCode, resp.Header.Get("Location"))
	}
	assertAuthMeUnauthorized(t, baseURL, jar2)
	// A NameID the mapping cannot place in a tenant signs nothing out.
	sloURL, form = idp.idpInitiatedLogoutForm(t, "nobody@example.test")
	resp, err = noFollowClient(nil).PostForm(sloURL, form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("IdP-initiated logout for an unmapped user = %d, want 403", resp.StatusCode)
	}
}

func csrfCookieValue(t *testing.T, jar http.CookieJar, baseURL string) string {
	t.Helper()
	u, _ := url.Parse(baseURL)
	for _, c := range jar.Cookies(u) {
		if strings.Contains(c.Name, "csrf") {
			return c.Value
		}
	}
	t.Fatal("no CSRF cookie after login")
	return ""
}

func assertAuthMeUnauthorized(t *testing.T, baseURL string, jar http.CookieJar) {
	t.Helper()
	resp, err := (&http.Client{Jar: jar}).Get(baseURL + "/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /auth/me after logout = %d, want 401", resp.StatusCode)
	}
}
