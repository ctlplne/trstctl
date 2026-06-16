package acmedns_test

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

	"trstctl.com/trstctl/internal/dns/acmedns"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testUser  = "00000000-0000-0000-0000-000000000000"
	testKey   = "acme-dns-apikey-do-not-log"
	subdomain = "0123abcd-4567-89ef-0123-456789abcdef"
)

// fakeACMEDNS is an in-process double of the acme-dns HTTP API, faithful to the two
// behaviors the provider depends on: it authenticates the X-Api-User / X-Api-Key
// pair the way real acme-dns does (rejecting a mismatch with 401), and on
// POST /update it stores the single most-recent TXT value for the subdomain,
// OVERWRITING any previous value and ignoring the (absent) record name. It also
// satisfies acme.Resolver: LookupTXT returns the current stored value REGARDLESS of
// the name asked for, because acme-dns serves one subdomain and the real
// _acme-challenge.<domain> is just a CNAME into it — so the DNS-01 validator reading
// back "_acme-challenge.conformance.example" sees the value the provider published.
type fakeACMEDNS struct {
	srv  *httptest.Server
	user string
	key  string

	mu      sync.Mutex
	txt     string // current stored TXT for the subdomain ("" => none)
	hasTxt  bool
	updates int // count of authenticated /update calls
}

func newFakeACMEDNS(user, key string) *fakeACMEDNS {
	f := &fakeACMEDNS{user: user, key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeACMEDNS) URL() string          { return f.srv.URL }
func (f *fakeACMEDNS) Client() *http.Client { return f.srv.Client() }
func (f *fakeACMEDNS) Close()               { f.srv.Close() }

func (f *fakeACMEDNS) Updates() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

// LookupTXT satisfies acme.Resolver. acme-dns serves the same subdomain regardless
// of the queried name, so the double returns the current stored value for ANY name.
func (f *fakeACMEDNS) LookupTXT(_ context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.hasTxt {
		return nil, nil
	}
	return []string{f.txt}, nil
}

func (f *fakeACMEDNS) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Api-User") != f.user || r.Header.Get("X-Api-Key") != f.key {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/update" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		SubDomain string `json:"subdomain"`
		Txt       string `json:"txt"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.SubDomain == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"bad request"}`)
		return
	}

	f.mu.Lock()
	f.txt = req.Txt // overwrite: acme-dns only holds the most-recent value
	f.hasTxt = true
	f.updates++
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"txt":"`+req.Txt+`"}`)
}

func newProvider(t *testing.T, f *fakeACMEDNS, creds acmedns.Credentials) *acmedns.Provider {
	t.Helper()
	return acmedns.New(subdomain, creds,
		acmedns.WithEndpoint(f.URL()),
		acmedns.WithHTTPClient(f.Client()))
}

func goodCreds() acmedns.Credentials {
	return acmedns.Credentials{Username: testUser, Password: []byte(testKey)}
}

// Why not acme.ConformDNSProvider here? That harness asserts a full
// present -> validate -> cleanup -> assert-validation-now-FAILS cycle. acme-dns has
// no delete endpoint, so CleanupTXT is necessarily a no-op and the published value
// stays resolvable; the harness's post-cleanup "must fail" assertion would
// therefore (correctly) fail for any acme-dns provider. So instead of the cleanup
// half, we assert the half that is meaningful for acme-dns: what PresentTXT
// publishes is exactly what the real DNS01Validator reads back and accepts.
//
// TestAcmeDNSPresentValidates: present a value, then drive the real
// acme.DNS01Validator (reading through the double) and require it to succeed —
// publish-side ⇄ verify-side agreement, the same property route53's conformance
// test checks, minus the cleanup assertion acme-dns can't satisfy.
func TestAcmeDNSPresentValidates(t *testing.T) {
	f := newFakeACMEDNS(testUser, testKey)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	ctx := context.Background()

	const domain, keyAuth = "conformance.example", "conformance-token.account-thumbprint"
	name := acme.DNS01RecordName(domain)
	value := acme.DNS01RecordValue(keyAuth)

	if err := p.PresentTXT(ctx, name, value); err != nil {
		t.Fatalf("present: %v", err)
	}
	if f.Updates() == 0 {
		t.Fatal("present ran but the double served no authenticated /update")
	}

	v := acme.DNS01Validator{Resolver: f}
	if err := v.Validate(ctx, acme.ChallengeDNS01, domain, "conformance-token", keyAuth); err != nil {
		t.Fatalf("published record did not validate: %v", err)
	}
}

// TestPresentIsIdempotent: acme-dns holds only the most-recent TXT, so re-POSTing
// the same value is a no-op at the zone level. Presenting twice must succeed and
// leave exactly one stored value, still equal to what was published (AN-5).
func TestPresentIsIdempotent(t *testing.T) {
	f := newFakeACMEDNS(testUser, testKey)
	defer f.Close()
	p := newProvider(t, f, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "token-digest-value"

	for i := 0; i < 2; i++ {
		if err := p.PresentTXT(ctx, name, value); err != nil {
			t.Fatalf("present #%d: %v", i+1, err)
		}
	}
	got, err := f.LookupTXT(ctx, name)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got) != 1 || got[0] != value {
		t.Fatalf("after idempotent present, stored = %v, want exactly [%q]", got, value)
	}

	// CleanupTXT is a documented no-op for acme-dns (no delete endpoint): it must
	// succeed and must NOT make a network call or change the stored value.
	updatesBefore := f.Updates()
	if err := p.CleanupTXT(ctx, name, value); err != nil {
		t.Fatalf("cleanup must be a no-op success: %v", err)
	}
	if f.Updates() != updatesBefore {
		t.Fatal("cleanup made a network call; it must be a pure no-op for acme-dns")
	}
	if got, _ := f.LookupTXT(ctx, name); len(got) != 1 || got[0] != value {
		t.Fatalf("cleanup altered the stored value; got %v", got)
	}
}

// TestBadCredentialsRejected: a wrong apikey must fail closed at the acme-dns auth
// check (the double rejects with 401 like real acme-dns), not silently succeed.
func TestBadCredentialsRejected(t *testing.T) {
	f := newFakeACMEDNS(testUser, testKey)
	defer f.Close()
	p := newProvider(t, f, acmedns.Credentials{Username: testUser, Password: []byte("wrong-apikey")})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong apikey succeeded; auth was not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the apikey,
// even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	f := newFakeACMEDNS(testUser, testKey)
	defer f.Close()
	const secret = "ultra-secret-acme-dns-apikey"
	p := newProvider(t, f, acmedns.Credentials{Username: testUser, Password: []byte(secret)})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched apikey")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the apikey: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to
// the acme-dns host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	f := newFakeACMEDNS(testUser, testKey)
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
		t.Errorf("net.dial grant should allow the acme-dns host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the acme-dns host only")
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
