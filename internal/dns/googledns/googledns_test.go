package googledns_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/dns/googledns"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testToken = "ya29.test-access-token-do-not-log"
	project   = "trstctl-test-project"
	zone      = "example-zone"
)

// fakeCloudDNS is an in-process double of the Google Cloud DNS API's
// managedZones/{zone}/changes endpoint, defined inline so the provider can be tested
// on CI without real GCP. It enforces the bearer credential the way the real service
// does (rejecting a missing or wrong token with 401), applies a Change's additions
// and deletions to an in-memory zone, and serves the published TXT records back
// (satisfying acme.Resolver) so the DNS-01 conformance harness can validate
// end-to-end. Deleting an rrset that is not present returns Cloud DNS's 404
// "notFound" so the provider's idempotent no-op path is exercised. No crypto/* (AN-3):
// a bearer token needs no signature to verify.
type fakeCloudDNS struct {
	srv   *httptest.Server
	token string

	mu      sync.Mutex
	records map[string]map[string]bool // fqdn name -> set of unquoted TXT values
	calls   int
}

func newFakeCloudDNS(token string) *fakeCloudDNS {
	s := &fakeCloudDNS{
		token:   token,
		records: map[string]map[string]bool{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeCloudDNS) URL() string          { return s.srv.URL }
func (s *fakeCloudDNS) Client() *http.Client { return s.srv.Client() }
func (s *fakeCloudDNS) Close()               { s.srv.Close() }

func (s *fakeCloudDNS) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *fakeCloudDNS) Records(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for v := range s.records[canonName(name)] {
		out = append(out, v)
	}
	return out
}

// LookupTXT satisfies acme.Resolver, returning the published values for name
// (unquoted) so the DNS-01 validator can read back what the provider wrote. It is
// trailing-dot-insensitive: the provider writes absolute names, the validator looks
// up the un-rooted form.
func (s *fakeCloudDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return s.Records(name), nil
}

type changeBody struct {
	Additions []resourceRecordSet `json:"additions"`
	Deletions []resourceRecordSet `json:"deletions"`
}

type resourceRecordSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

func (s *fakeCloudDNS) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/changes") {
		s.fail(w, http.StatusNotFound, "notFound", "no such resource")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid authentication credentials")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	var req changeBody
	if err := json.Unmarshal(body, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "invalid", "malformed change")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++

	// Additions: reject (409 alreadyExists) if the exact rrdata is already present,
	// matching Cloud DNS; otherwise store the unquoted value.
	for _, rrs := range req.Additions {
		if !strings.EqualFold(rrs.Type, "TXT") {
			continue
		}
		name := canonName(rrs.Name)
		for _, rd := range rrs.RRDatas {
			v := unquote(rd)
			if s.records[name][v] {
				s.fail(w, http.StatusConflict, "alreadyExists",
					"The resource record set already exists")
				return
			}
		}
		if s.records[name] == nil {
			s.records[name] = map[string]bool{}
		}
		for _, rd := range rrs.RRDatas {
			s.records[name][unquote(rd)] = true
		}
	}

	// Deletions: reject (404 notFound) if the rrset/rrdata is absent, matching Cloud
	// DNS, so the provider's no-op cleanup path is exercised; otherwise remove it.
	for _, rrs := range req.Deletions {
		if !strings.EqualFold(rrs.Type, "TXT") {
			continue
		}
		name := canonName(rrs.Name)
		vs := s.records[name]
		for _, rd := range rrs.RRDatas {
			v := unquote(rd)
			if !vs[v] {
				s.fail(w, http.StatusNotFound, "notFound",
					"The resource record set was not found")
				return
			}
		}
		for _, rd := range rrs.RRDatas {
			delete(vs, unquote(rd))
		}
		if len(vs) == 0 {
			delete(s.records, name)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"kind":"dns#change","status":"done"}`)
}

func (s *fakeCloudDNS) fail(w http.ResponseWriter, status int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Mirror the shape of a Cloud DNS error: a top-level message plus a per-error
	// reason. The provider matches on the reason/message text.
	_, _ = io.WriteString(w, `{"error":{"code":`+strconv.Itoa(status)+
		`,"message":"`+msg+`","errors":[{"reason":"`+reason+`","message":"`+msg+`"}]}}`)
}

// canonName normalizes a record name for comparison: Cloud DNS stores absolute
// (trailing-dot) names, but the solver and validator use the un-rooted form.
func canonName(name string) string { return strings.TrimSuffix(name, ".") }

// unquote strips the surrounding double quotes Cloud DNS stores TXT rrdatas under, so
// LookupTXT returns the raw authorization value the validator expects.
func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

func newProvider(t *testing.T, srv *fakeCloudDNS, creds googledns.Credentials) *googledns.Provider {
	t.Helper()
	return googledns.New(project, zone, creds,
		googledns.WithEndpoint(srv.URL()),
		googledns.WithHTTPClient(srv.Client()))
}

func goodCreds() googledns.Credentials {
	return googledns.Credentials{BearerToken: testToken}
}

// TestGoogleDNSPassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// bearer-verifying double. Cleanup is asserted, not just issuance.
func TestGoogleDNSPassesConformance(t *testing.T) {
	srv := newFakeCloudDNS(testToken)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, srv); err != nil {
		t.Fatalf("Cloud DNS provider failed DNS-01 conformance: %v", err)
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice hits the alreadyExists path and still leaves exactly one record,
// and cleaning up twice (the second time the record is already gone, exercising the
// notFound no-op) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	srv := newFakeCloudDNS(testToken)
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

// TestBadTokenRejected: a wrong bearer token must fail closed at the auth check (the
// double rejects it with 401 like the real service), not silently succeed.
func TestBadTokenRejected(t *testing.T) {
	srv := newFakeCloudDNS(testToken)
	defer srv.Close()
	p := newProvider(t, srv, googledns.Credentials{BearerToken: "wrong-token"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong token succeeded; bearer auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 auth rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the bearer
// token, even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	srv := newFakeCloudDNS(testToken)
	defer srv.Close()
	const secret = "ya29.ultra-secret-token-material"
	// Point the double at a different token so the request fails and surfaces an error.
	p := newProvider(t, srv, googledns.Credentials{BearerToken: secret})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched token")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the bearer token: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// Cloud DNS host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := newFakeCloudDNS(testToken)
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
		t.Errorf("net.dial grant should allow the Cloud DNS host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the Cloud DNS host only")
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
