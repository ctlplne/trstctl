package ns1_test

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

	"trstctl.com/trstctl/internal/dns/ns1"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testAPIKey = "ns1-api-key-do-not-log"
	testZone   = "example.com"
)

// fakeNS1 is an in-process double of the NS1 v1 records API, faithful to the parts
// the provider exercises: it authenticates the X-NSONE-Key header the way real NS1
// does (rejecting a wrong key with 401), applies PUT (create-or-replace) and DELETE
// (404 when already gone) to an in-memory zone keyed by record name, and serves the
// stored TXT values back via LookupTXT so the DNS-01 conformance harness can validate
// end-to-end (it satisfies acme.Resolver).
type fakeNS1 struct {
	srv    *httptest.Server
	apiKey string

	mu      sync.Mutex
	records map[string][]string // record name (un-rooted) -> TXT answer values
	calls   int
}

func newFakeNS1(apiKey string) *fakeNS1 {
	f := &fakeNS1{apiKey: apiKey, records: map[string][]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeNS1) URL() string          { return f.srv.URL }
func (f *fakeNS1) Client() *http.Client { return f.srv.Client() }
func (f *fakeNS1) Close()               { f.srv.Close() }

// Calls is the number of authenticated record requests served.
func (f *fakeNS1) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// LookupTXT satisfies acme.Resolver, returning the values stored under name so the
// DNS-01 validator can read back what the provider wrote.
func (f *fakeNS1) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.records[canon(name)]...)
	return out, nil
}

func (f *fakeNS1) handle(w http.ResponseWriter, r *http.Request) {
	// Authenticate exactly like real NS1: a missing or wrong key is 401, never a
	// silent success.
	if r.Header.Get("X-NSONE-Key") != f.apiKey {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
		return
	}

	name, ok := recordName(r.URL.Path, testZone)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "record not found"})
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var rb struct {
			Answers []struct {
				Answer []string `json:"answer"`
			} `json:"answers"`
		}
		if err := json.Unmarshal(body, &rb); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "malformed record"})
			return
		}
		// PUT is create-or-replace.
		var vals []string
		for _, a := range rb.Answers {
			vals = append(vals, a.Answer...)
		}
		f.records[name] = vals
		writeJSON(w, http.StatusOK, map[string]string{"type": "TXT", "domain": name})

	case http.MethodDelete:
		if _, present := f.records[name]; !present {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "record not found"})
			return
		}
		delete(f.records, name)
		writeJSON(w, http.StatusOK, map[string]string{})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "method not allowed"})
	}
}

// recordName extracts the record name from an NS1 records path of the form
// /v1/zones/{zone}/{name}/TXT (the leading prefix is whatever WithEndpoint set).
func recordName(path, zone string) (string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// Find the "zones" segment, then expect it to be followed by zone, name, "TXT".
	for i := 0; i+3 < len(parts); i++ {
		if parts[i] != "zones" {
			continue
		}
		if parts[i+1] != zone || !strings.EqualFold(parts[i+3], "TXT") {
			return "", false
		}
		return canon(parts[i+2]), true
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// canon normalizes a record name for comparison (NS1 may carry a trailing dot; the
// solver and validator use the un-rooted form).
func canon(name string) string { return strings.TrimSuffix(name, ".") }

func newProvider(t *testing.T, f *fakeNS1, creds ns1.Credentials) *ns1.Provider {
	t.Helper()
	return ns1.New(testZone, creds,
		ns1.WithEndpoint(f.URL()),
		ns1.WithHTTPClient(f.Client()))
}

func goodCreds() ns1.Credentials { return ns1.Credentials{APIKey: testAPIKey} }

// TestNS1PassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// key-verifying double. Cleanup is asserted, not just issuance.
func TestNS1PassesConformance(t *testing.T) {
	f := newFakeNS1(testAPIKey)
	defer f.Close()
	p := newProvider(t, f, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, f); err != nil {
		t.Fatalf("NS1 provider failed DNS-01 conformance: %v", err)
	}
	if f.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice is a no-op (PUT is create-or-replace), and cleaning up twice (the
// second time the record is already gone -> 404) still succeeds and leaves the zone
// empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	f := newFakeNS1(testAPIKey)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "token-digest-value"

	for i := 0; i < 2; i++ {
		if err := p.PresentTXT(ctx, name, value); err != nil {
			t.Fatalf("present #%d: %v", i+1, err)
		}
	}
	if got, _ := f.LookupTXT(ctx, name); len(got) != 1 || got[0] != value {
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

// TestBadKeyRejected: a wrong API key must fail closed at the auth check (the double
// rejects it like real NS1 with 401), not silently succeed.
func TestBadKeyRejected(t *testing.T) {
	f := newFakeNS1(testAPIKey)
	defer f.Close()
	p := newProvider(t, f, ns1.Credentials{APIKey: "wrong-key"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong API key succeeded; auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the API key,
// even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	f := newFakeNS1(testAPIKey)
	defer f.Close()
	const secret = "ultra-secret-ns1-api-key"
	p := newProvider(t, f, ns1.Credentials{APIKey: secret})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched API key")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the API key: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// NS1 API host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	f := newFakeNS1(testAPIKey)
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
		t.Errorf("net.dial grant should allow the NS1 host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the NS1 host only")
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
