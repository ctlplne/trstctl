package akamai_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dns/akamai"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	zone             = "example.com"
	testClientToken  = "akab-client-token-xxxx"
	testAccessToken  = "akab-access-token-xxxx"
	testClientSecret = "edgegrid-client-secret-do-not-log"

	// fixedTimestamp / fixedNonce are injected into both the provider and the double
	// so the EdgeGrid signature is deterministic and the two agree exactly.
	fixedTimestamp = "20260613T12:00:00+0000"
	fixedNonce     = "00000000-0000-4000-8000-000000000000"

	edgeGridTimeFormat = "20060102T15:04:05+0000"
)

// --- the verifying Akamai double --------------------------------------------------
//
// fakeAkamai is an in-process double of the Akamai Edge DNS Zone Management API. Like
// r53test verifies AWS SigV4, it verifies the request's EdgeGrid (EG1-HMAC-SHA256)
// signature the way the real service does — it parses the Authorization header,
// reconstructs the exact data-to-sign from the received request, recomputes the
// signature under the test client secret, and rejects a mismatch with 401 — so a
// canonical / content-hash / signing-key bug in the provider's signer is caught here,
// not papered over. It applies PUT/DELETE of TXT record sets to an in-memory zone
// (unquoting on store) and serves the published values back, satisfying acme.Resolver
// so the DNS-01 conformance harness can validate end-to-end. No crypto/* (AN-3): the
// keyed MAC and digest route through the crypto boundary, the same primitives the
// provider uses.
type fakeAkamai struct {
	srv          *httptest.Server
	clientToken  string
	accessToken  string
	clientSecret string

	mu      sync.Mutex
	records map[string]map[string]bool // record name -> set of unquoted TXT values
	calls   int
}

func newFakeAkamai(clientToken, accessToken, clientSecret string) *fakeAkamai {
	f := &fakeAkamai{
		clientToken:  clientToken,
		accessToken:  accessToken,
		clientSecret: clientSecret,
		records:      map[string]map[string]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeAkamai) URL() string          { return f.srv.URL }
func (f *fakeAkamai) Client() *http.Client { return f.srv.Client() }
func (f *fakeAkamai) Close()               { f.srv.Close() }

func (f *fakeAkamai) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Records returns the TXT values currently published for name (unquoted).
func (f *fakeAkamai) Records(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for v := range f.records[canonName(name)] {
		out = append(out, v)
	}
	return out
}

// LookupTXT satisfies acme.Resolver, returning the published values for name so the
// DNS-01 validator can read back what the provider wrote.
func (f *fakeAkamai) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.Records(name), nil
}

func (f *fakeAkamai) handle(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.URL.Path, "/config-dns/v2/zones/") || !strings.HasSuffix(r.URL.Path, "/types/TXT") {
		http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	if !f.verifyEdgeGrid(r, body) {
		http.Error(w, `{"detail":"invalid EdgeGrid signature"}`, http.StatusUnauthorized)
		return
	}

	name := canonName(nameFromPath(r.URL.Path))

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	switch r.Method {
	case http.MethodPut:
		var rec recordBody
		if err := json.Unmarshal(body, &rec); err != nil {
			http.Error(w, `{"detail":"malformed record"}`, http.StatusBadRequest)
			return
		}
		if f.records[name] == nil {
			f.records[name] = map[string]bool{}
		}
		for _, rd := range rec.RData {
			f.records[name][unquote(rd)] = true
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"name":"`+name+`","type":"TXT"}`)
	case http.MethodDelete:
		if f.records[name] == nil {
			http.Error(w, `{"detail":"record set not found"}`, http.StatusNotFound)
			return
		}
		delete(f.records, name)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, `{"detail":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// verifyEdgeGrid reconstructs the data-to-sign from the received request and the
// timestamp+nonce carried in the Authorization header, recomputes the signature under
// the test client secret, and compares it to the one presented — exactly the server
// side of EdgeGrid. This logic is intentionally identical to the provider's signer.
func (f *fakeAkamai) verifyEdgeGrid(r *http.Request, body []byte) bool {
	const algo = "EG1-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return false
	}
	fields := parseAuthFields(auth[len(algo):])
	ct, at := fields["client_token"], fields["access_token"]
	ts, nonce, sig := fields["timestamp"], fields["nonce"], fields["signature"]
	if ct == "" || at == "" || ts == "" || nonce == "" || sig == "" {
		return false
	}
	// The credentials presented must be the ones we issued.
	if ct != f.clientToken || at != f.accessToken {
		return false
	}

	authData := edgeGridAuthData(ct, at, ts, nonce)
	dataToSign := edgeGridDataToSign(r.Method, r.Host, edgeGridRelativeURL(r.URL), body, authData)
	want := edgeGridSign(f.clientSecret, ts, dataToSign)
	return want == sig
}

// --- EdgeGrid signing primitives (must mirror the provider's exactly) -------------

func edgeGridAuthData(clientToken, accessToken, timestamp, nonce string) string {
	return "EG1-HMAC-SHA256 " +
		"client_token=" + clientToken + ";" +
		"access_token=" + accessToken + ";" +
		"timestamp=" + timestamp + ";" +
		"nonce=" + nonce + ";" +
		"signature="
}

func edgeGridRelativeURL(u *url.URL) string {
	rel := u.EscapedPath()
	if u.RawQuery != "" {
		rel += "?" + u.RawQuery
	}
	return rel
}

func edgeGridContentHash(method string, body []byte) string {
	if method != http.MethodPost && method != http.MethodPut {
		return ""
	}
	return base64.StdEncoding.EncodeToString(crypto.SHA256Sum(body))
}

func edgeGridDataToSign(method, host, relativeURL string, body []byte, authData string) string {
	return strings.Join([]string{
		method,
		"https",
		host,
		relativeURL,
		"",
		edgeGridContentHash(method, body),
		authData,
	}, "\t")
}

func edgeGridSigningKey(clientSecret, timestamp string) string {
	return base64.StdEncoding.EncodeToString(
		crypto.HMACSHA256([]byte(clientSecret), []byte(timestamp)))
}

func edgeGridSign(clientSecret, timestamp, dataToSign string) string {
	signingKey := edgeGridSigningKey(clientSecret, timestamp)
	return base64.StdEncoding.EncodeToString(
		crypto.HMACSHA256([]byte(signingKey), []byte(dataToSign)))
}

// parseAuthFields splits the EdgeGrid "k=v;k=v;...signature=<sig>" body. The final
// signature value may be empty (during reconstruction) or set (as received).
func parseAuthFields(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		if kv == "" {
			continue
		}
		k, v, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		out[k] = v
	}
	return out
}

func nameFromPath(path string) string {
	// .../zones/{zone}/names/{name}/types/TXT
	const marker = "/names/"
	i := strings.Index(path, marker)
	if i < 0 {
		return ""
	}
	rest := path[i+len(marker):]
	if j := strings.Index(rest, "/types/"); j >= 0 {
		rest = rest[:j]
	}
	if dec, err := url.PathUnescape(rest); err == nil {
		return dec
	}
	return rest
}

func canonName(name string) string { return strings.TrimSuffix(name, ".") }

func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

type recordBody struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	TTL   int      `json:"ttl"`
	RData []string `json:"rdata"`
}

// --- test helpers -----------------------------------------------------------------

func fixedClock() time.Time {
	t, err := time.Parse(edgeGridTimeFormat, fixedTimestamp)
	if err != nil {
		panic(err)
	}
	return t
}

func goodCreds() akamai.Credentials {
	return akamai.Credentials{
		ClientToken:  testClientToken,
		ClientSecret: testClientSecret,
		AccessToken:  testAccessToken,
	}
}

// newProvider builds an Akamai provider pointed at the double, with the deterministic
// clock and nonce the double also assumes, so client and server signatures agree.
func newProvider(t *testing.T, srv *fakeAkamai, creds akamai.Credentials) *akamai.Provider {
	t.Helper()
	return akamai.New(zone, creds,
		akamai.WithEndpoint(srv.URL()),
		akamai.WithHTTPClient(srv.Client()),
		akamai.WithClock(fixedClock),
		akamai.WithNonce(func() string { return fixedNonce }))
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}

// --- tests ------------------------------------------------------------------------

// TestAkamaiPassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// EdgeGrid-verifying double. Cleanup is asserted, not just issuance.
func TestAkamaiPassesConformance(t *testing.T) {
	srv := newFakeAkamai(testClientToken, testAccessToken, testClientSecret)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, srv); err != nil {
		t.Fatalf("Akamai provider failed DNS-01 conformance: %v", err)
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice is a no-op, and cleaning up twice (the second time the record is
// already gone) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	srv := newFakeAkamai(testClientToken, testAccessToken, testClientSecret)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "token-digest-value"

	for i := 0; i < 2; i++ {
		if err := p.PresentTXT(ctx, name, value); err != nil {
			t.Fatalf("present #%d: %v", i+1, err)
		}
	}
	if got := srv.Records(name); len(got) != 1 || got[0] != value {
		t.Fatalf("after idempotent present, records = %v, want exactly [%q]", got, value)
	}
	for i := 0; i < 2; i++ {
		if err := p.CleanupTXT(ctx, name, value); err != nil {
			t.Fatalf("cleanup #%d (must be idempotent): %v", i+1, err)
		}
	}
	if got := srv.Records(name); len(got) != 0 {
		t.Fatalf("after cleanup, records = %v, want none", got)
	}
}

// TestBadSecretRejected: a wrong client secret must fail closed at the EdgeGrid
// signature check (the double verifies the signature like real Akamai), not silently
// succeed.
func TestBadSecretRejected(t *testing.T) {
	srv := newFakeAkamai(testClientToken, testAccessToken, testClientSecret)
	defer srv.Close()
	bad := akamai.Credentials{
		ClientToken:  testClientToken,
		ClientSecret: "wrong-client-secret",
		AccessToken:  testAccessToken,
	}
	p := newProvider(t, srv, bad)

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong client secret succeeded; EdgeGrid was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 signature rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak any of the
// EdgeGrid credentials, even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	srv := newFakeAkamai(testClientToken, testAccessToken, testClientSecret)
	defer srv.Close()
	const secret = "ultra-secret-edgegrid-material"
	creds := akamai.Credentials{
		ClientToken:  "ct-secret-token-value",
		ClientSecret: secret,
		AccessToken:  "at-secret-token-value",
	}
	p := newProvider(t, srv, creds)

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched secret")
	}
	for _, leak := range []string{secret, creds.ClientToken, creds.AccessToken} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaked a credential (%q): %v", leak, err)
		}
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// Akamai host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := newFakeAkamai(testClientToken, testAccessToken, testClientSecret)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())
	g := p.Capabilities()

	if !g.Has(pluginhost.CapNetDial) {
		t.Error("provider must declare net.dial")
	}
	if g.Has(pluginhost.CapFSRead) || g.Has(pluginhost.CapFSWrite) {
		t.Error("provider must not declare filesystem capabilities")
	}
	host := mustHost(t, srv.URL())
	if !g.Allows(pluginhost.CapNetDial, host) {
		t.Errorf("net.dial grant should allow the Akamai host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the Akamai host only")
	}
}

// guard: the provider implements the DNS-01 plugin template.
var _ acme.DNSProvider = (*akamai.Provider)(nil)
