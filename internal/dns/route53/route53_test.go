package route53_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/dns/route53"
	"trstctl.com/trstctl/internal/dns/route53/r53test"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testAK = "AKIAR53TEST"
	testSK = "secret-r53-key-do-not-log"
	zoneID = "Z0123456789ABCDEFGHIJ"
)

func newProvider(t *testing.T, srv *r53test.Server, creds route53.Credentials) *route53.Provider {
	t.Helper()
	return route53.New(zoneID, creds,
		route53.WithEndpoint(srv.URL()),
		route53.WithHTTPClient(srv.Client()))
}

func goodCreds() route53.Credentials {
	return route53.Credentials{AccessKeyID: testAK, SecretAccessKey: testSK}
}

// TestRoute53PassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against
// the SigV4-verifying double. Cleanup is asserted, not just issuance.
func TestRoute53PassesConformance(t *testing.T) {
	srv := r53test.New(testAK, testSK)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, srv); err != nil {
		t.Fatalf("Route 53 provider failed DNS-01 conformance: %v", err)
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records
// (AN-5): presenting twice is a no-op, and cleaning up twice (the second time the
// record is already gone) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	srv := r53test.New(testAK, testSK)
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

// TestBadCredentialsRejected: a wrong secret must fail closed at the SigV4 check
// (the double verifies the signature like real Route 53), not silently succeed.
func TestBadCredentialsRejected(t *testing.T) {
	srv := r53test.New(testAK, testSK)
	defer srv.Close()
	p := newProvider(t, srv, route53.Credentials{AccessKeyID: testAK, SecretAccessKey: "wrong-secret"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong secret succeeded; SigV4 was not enforced")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("want a 403 signature rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the secret
// access key, even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	srv := r53test.New(testAK, testSK)
	defer srv.Close()
	const secret = "ultra-secret-key-material"
	p := newProvider(t, srv, route53.Credentials{AccessKeyID: testAK, SecretAccessKey: secret})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched secret")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the secret access key: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to
// the Route 53 host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := r53test.New(testAK, testSK)
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
		t.Errorf("net.dial grant should allow the Route 53 host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the Route 53 host only")
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

// TestSignedRequestRoutesThroughCloudhttpBound proves the SIGNING provider shares the
// same cloudhttp core (CODE-006): the SigV4 signature is still applied (the server
// observes an Authorization header it can recover), AND the non-2xx error body the
// provider surfaces is bounded by the SHARED cloudhttp.MaxErrorBytes — not a bespoke
// per-provider literal. Lowering cloudhttp.MaxErrorBytes changes what route53 (a
// signing provider) observes, because its bounded read is now central. The request is
// still SigV4-signed via the cloudhttp request-signer seam — the keyed MAC stays in
// the provider, behind the crypto boundary (AN-3).
func TestSignedRequestRoutesThroughCloudhttpBound(t *testing.T) {
	huge := strings.Repeat("E", cloudhttp.MaxErrorBytes*3)
	var sawSigV4 bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The cloudhttp signer ran iff the request carries the SigV4 Authorization
		// header — proving the signing seam is wired into the shared round-trip.
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") &&
			r.Header.Get("X-Amz-Date") != "" {
			sawSigV4 = true
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, huge)
	}))
	defer srv.Close()

	p := route53.New(zoneID, goodCreds(),
		route53.WithEndpoint(srv.URL), route53.WithHTTPClient(srv.Client()))

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the 502 upstream")
	}
	if !sawSigV4 {
		t.Fatal("server saw no SigV4 Authorization header — the signer seam is not wired into cloudhttp (CODE-006)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "502") {
		t.Fatalf("error should carry the upstream status: %v", err)
	}
	bodyLen := strings.Count(msg, "E")
	if bodyLen == 0 {
		t.Fatal("error carried no body snippet; the shared bounded read did not run")
	}
	if bodyLen > cloudhttp.MaxErrorBytes {
		t.Fatalf("error body = %d 'E's, exceeds the shared cloudhttp.MaxErrorBytes cap %d — the bound is not centrally applied to the signing provider (CODE-006)", bodyLen, cloudhttp.MaxErrorBytes)
	}
}
