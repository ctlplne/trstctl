package ultradns_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/dns/ultradns"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testToken = "ultradns-oauth2-bearer-token-do-not-log"
	testZone  = "example.com"
)

// fakeUltraDNS is an in-process double of the UltraDNS REST rrsets API, faithful
// enough to test the provider on CI without a real account. It checks the bearer
// token the way the real service does (rejecting a wrong/absent token with 401),
// applies PUT upsert / DELETE to an in-memory zone storing the *unquoted* TXT value,
// and serves the published records back via LookupTXT so it satisfies acme.Resolver
// and the DNS-01 conformance harness can validate end-to-end.
type fakeUltraDNS struct {
	srv   *httptest.Server
	token string

	mu      sync.Mutex
	records map[string]map[string]bool // record name -> set of unquoted TXT values
	calls   int
}

func newFake(token string) *fakeUltraDNS {
	f := &fakeUltraDNS{token: token, records: map[string]map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

// URL is the endpoint base URL of the fake service.
func (f *fakeUltraDNS) URL() string { return f.srv.URL }

// Client returns an HTTP client for the fake service.
func (f *fakeUltraDNS) Client() *http.Client { return f.srv.Client() }

// Close shuts the server down.
func (f *fakeUltraDNS) Close() { f.srv.Close() }

func (f *fakeUltraDNS) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// LookupTXT satisfies acme.Resolver, returning the unquoted values published for
// name so the DNS-01 validator can read back what the provider wrote.
func (f *fakeUltraDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for v := range f.records[canonName(name)] {
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeUltraDNS) handle(w http.ResponseWriter, r *http.Request) {
	// Fail closed on a missing or wrong bearer token, like the real service.
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"errorCode":60001,"errorMessage":"invalid bearer token"}`, http.StatusUnauthorized)
		return
	}

	// Path: /zones/{zone}/rrsets/TXT/{name}
	const marker = "/rrsets/TXT/"
	i := strings.Index(r.URL.Path, marker)
	if i < 0 {
		http.Error(w, `{"errorCode":70001,"errorMessage":"resource not found"}`, http.StatusNotFound)
		return
	}
	name := canonName(r.URL.Path[i+len(marker):])

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	switch r.Method {
	case http.MethodPut:
		var body struct {
			TTL   int      `json:"ttl"`
			RData []string `json:"rdata"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, `{"errorCode":50001,"errorMessage":"malformed rrset"}`, http.StatusBadRequest)
			return
		}
		// PUT is an upsert of the whole rrset: replace any existing values.
		set := map[string]bool{}
		for _, rd := range body.RData {
			set[unquote(rd)] = true
		}
		f.records[name] = set
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"Successful"}`)

	case http.MethodDelete:
		if _, ok := f.records[name]; !ok {
			// Real UltraDNS returns 404 deleting an absent rrset; the provider
			// treats this as a no-op so cleanup stays idempotent.
			http.Error(w, `{"errorCode":70001,"errorMessage":"rrset not found"}`, http.StatusNotFound)
			return
		}
		delete(f.records, name)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, `{"errorCode":50002,"errorMessage":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// canonName normalizes a record name for comparison: a TXT name may carry a trailing
// dot, but the solver and validator use the un-rooted form.
func canonName(name string) string { return strings.TrimSuffix(name, ".") }

// unquote strips the surrounding double quotes UltraDNS stores TXT rdata under, so
// LookupTXT returns the raw authorization value the validator expects.
func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

func newProvider(t *testing.T, f *fakeUltraDNS, creds ultradns.Credentials) *ultradns.Provider {
	t.Helper()
	return ultradns.New(testZone, creds,
		ultradns.WithEndpoint(f.URL()),
		ultradns.WithHTTPClient(f.Client()))
}

func goodCreds() ultradns.Credentials {
	return ultradns.Credentials{BearerToken: testToken}
}

// TestUltraDNSPassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// bearer-token-verifying double. Cleanup is asserted, not just issuance.
func TestUltraDNSPassesConformance(t *testing.T) {
	f := newFake(testToken)
	defer f.Close()
	p := newProvider(t, f, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, f); err != nil {
		t.Fatalf("UltraDNS provider failed DNS-01 conformance: %v", err)
	}
	if f.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice is a no-op, and cleaning up twice (the second time the rrset is
// already gone) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	f := newFake(testToken)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "token-digest-value"

	for i := 0; i < 2; i++ {
		if err := p.PresentTXT(ctx, name, value); err != nil {
			t.Fatalf("present #%d: %v", i+1, err)
		}
	}
	got, _ := f.LookupTXT(ctx, name)
	if len(got) != 1 || got[0] != value {
		t.Fatalf("after idempotent present, records = %v, want exactly [%q]", got, value)
	}
	for i := 0; i < 2; i++ {
		if err := p.CleanupTXT(ctx, name, value); err != nil {
			t.Fatalf("cleanup #%d (must be idempotent): %v", i+1, err)
		}
	}
	if got, _ := f.LookupTXT(ctx, name); len(got) != 0 {
		t.Fatalf("after cleanup, records = %v, want none", got)
	}
}

// TestBadTokenRejected: a wrong bearer token must fail closed at the API auth check
// (the double rejects it like real UltraDNS), not silently succeed.
func TestBadTokenRejected(t *testing.T) {
	f := newFake(testToken)
	defer f.Close()
	p := newProvider(t, f, ultradns.Credentials{BearerToken: "wrong-token"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong bearer token succeeded; auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 auth rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the bearer
// token, even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	f := newFake(testToken)
	defer f.Close()
	const secret = "ultra-secret-bearer-material"
	p := newProvider(t, f, ultradns.Credentials{BearerToken: secret})

	// A mismatched token drives the failure path (the double expects testToken).
	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched bearer token")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the bearer token: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// UltraDNS host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	f := newFake(testToken)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	g := p.Capabilities()

	if !g.Has(pluginhost.CapNetDial) {
		t.Error("provider must declare net.dial")
	}
	if g.Has(pluginhost.CapFSRead) || g.Has(pluginhost.CapFSWrite) {
		t.Error("provider must not declare filesystem capabilities")
	}
	host := mustHost(t, f.URL())
	if !g.Allows(pluginhost.CapNetDial, host) {
		t.Errorf("net.dial grant should allow the UltraDNS host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the UltraDNS host only")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}
