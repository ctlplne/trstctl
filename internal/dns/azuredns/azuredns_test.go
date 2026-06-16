package azuredns_test

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

	"trstctl.com/trstctl/internal/dns/azuredns"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testToken      = "aad-access-token-do-not-log"
	subscriptionID = "00000000-0000-0000-0000-000000000000"
	resourceGroup  = "rg-trstctl"
	// zone is deliberately "example" so that for the conformance domain
	// "conformance.example" the FQDN "_acme-challenge.conformance.example" maps to a
	// stable relative name ("_acme-challenge.conformance") on both the provider and
	// the double.
	testZone = "example"
)

// fakeAzure is an in-process double of the Azure DNS record-set API, faithful enough
// to drive the DNS-01 conformance harness. It verifies the bearer token the way the
// real service does (rejecting a mismatch with 401), applies PUT upserts and DELETEs
// to an in-memory zone keyed by the record set's relative name, and serves the
// published TXT values back via LookupTXT (satisfying acme.Resolver) so the validator
// can read what the provider wrote.
//
// Critically, LookupTXT derives the relative name from the FQDN with the SAME
// transform the provider uses, so the publish side and the verify side can never
// drift: a record published at relative name R for FQDN F is found again by looking
// up F.
type fakeAzure struct {
	srv   *httptest.Server
	token string
	zone  string

	mu      sync.Mutex
	records map[string]map[string]bool // relative name -> set of TXT values
	calls   int
}

func newFakeAzure(token, zone string) *fakeAzure {
	f := &fakeAzure{
		token:   token,
		zone:    strings.TrimSuffix(zone, "."),
		records: map[string]map[string]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeAzure) URL() string { return f.srv.URL }

func (f *fakeAzure) Client() *http.Client { return f.srv.Client() }

func (f *fakeAzure) Close() { f.srv.Close() }

func (f *fakeAzure) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// relativeName mirrors azuredns.Provider.relativeName exactly: strip a trailing dot
// and the trailing "."+zone, with the apex collapsing to "@". Keeping the two in
// lockstep is what makes conformance round-trip.
func (f *fakeAzure) relativeName(name string) string {
	n := strings.TrimSuffix(name, ".")
	if n == f.zone {
		return "@"
	}
	if rel := strings.TrimSuffix(n, "."+f.zone); rel != n {
		return rel
	}
	return n
}

// LookupTXT satisfies acme.Resolver: it maps the FQDN back to the stored relative
// name and returns the published values, so the DNS-01 validator reads back exactly
// what PresentTXT wrote.
func (f *fakeAzure) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for v := range f.records[f.relativeName(name)] {
		out = append(out, v)
	}
	return out, nil
}

func (f *fakeAzure) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":"AuthenticationFailed","message":"invalid bearer token"}}`,
			http.StatusUnauthorized)
		return
	}

	// Pull the relative record-set name out of the .../TXT/{rel} path; reject
	// anything that is not a TXT record-set URL.
	rel, ok := txtRelFromPath(r.URL.Path)
	if !ok {
		http.Error(w, `{"error":{"code":"NotFound","message":"not a TXT record set"}}`,
			http.StatusNotFound)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	switch r.Method {
	case http.MethodPut:
		var rs struct {
			Properties struct {
				TXTRecords []struct {
					Value []string `json:"value"`
				} `json:"TXTRecords"`
			} `json:"properties"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(body, &rs); err != nil {
			http.Error(w, `{"error":{"code":"BadRequest","message":"malformed body"}}`,
				http.StatusBadRequest)
			return
		}
		// PUT is a whole-record-set upsert: replace whatever was there.
		set := map[string]bool{}
		for _, rec := range rs.Properties.TXTRecords {
			for _, v := range rec.Value {
				set[v] = true
			}
		}
		f.records[rel] = set
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"properties":{}}`)

	case http.MethodDelete:
		if _, present := f.records[rel]; !present {
			// Already gone — the provider must treat this as a no-op.
			http.Error(w, `{"error":{"code":"NotFound","message":"record set not found"}}`,
				http.StatusNotFound)
			return
		}
		delete(f.records, rel)
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, `{"error":{"code":"MethodNotAllowed","message":"unsupported"}}`,
			http.StatusMethodNotAllowed)
	}
}

// txtRelFromPath extracts {rel} from a path of the shape
// .../dnsZones/{zone}/TXT/{rel}, URL-decoding it. ok is false if the path has no
// /TXT/ record-set segment.
func txtRelFromPath(p string) (rel string, ok bool) {
	const marker = "/TXT/"
	i := strings.Index(p, marker)
	if i < 0 {
		return "", false
	}
	seg := p[i+len(marker):]
	if seg == "" {
		return "", false
	}
	if dec, err := url.PathUnescape(seg); err == nil {
		seg = dec
	}
	return seg, true
}

func newProvider(t *testing.T, f *fakeAzure, creds azuredns.Credentials) *azuredns.Provider {
	t.Helper()
	return azuredns.New(subscriptionID, resourceGroup, testZone, creds,
		azuredns.WithEndpoint(f.URL()),
		azuredns.WithHTTPClient(f.Client()))
}

func goodCreds() azuredns.Credentials {
	return azuredns.Credentials{BearerToken: testToken}
}

// TestAzureDNSPassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// token-verifying double. Cleanup is asserted, not just issuance.
func TestAzureDNSPassesConformance(t *testing.T) {
	f := newFakeAzure(testToken, testZone)
	defer f.Close()
	p := newProvider(t, f, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, f); err != nil {
		t.Fatalf("Azure DNS provider failed DNS-01 conformance: %v", err)
	}
	if f.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice is a no-op (PUT upsert), and cleaning up twice (the second time
// the record set is already gone, a 404) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	f := newFakeAzure(testToken, testZone)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.host.example", "token-digest-value"

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

// TestBadTokenRejected: a wrong bearer token must fail closed at the auth check (the
// double rejects with 401 like real Azure), not silently succeed.
func TestBadTokenRejected(t *testing.T) {
	f := newFakeAzure(testToken, testZone)
	defer f.Close()
	p := newProvider(t, f, azuredns.Credentials{BearerToken: "wrong-token"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.host.example", "v")
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
	f := newFakeAzure(testToken, testZone)
	defer f.Close()
	const secret = "ultra-secret-bearer-token-material"
	// The double is configured to expect a *different* token, so the provider's
	// secret token travels on the wire and the request fails — exercising the error
	// path with the real secret in play.
	p := newProvider(t, f, azuredns.Credentials{BearerToken: secret})

	err := p.PresentTXT(context.Background(), "_acme-challenge.host.example", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched token")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the bearer token: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// Azure management host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	f := newFakeAzure(testToken, testZone)
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
		t.Errorf("net.dial grant should allow the Azure management host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the Azure management host only")
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
