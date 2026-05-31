package acme_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto/acmekey"
	"certctl.io/certctl/internal/crypto/certinfo"
	acmesrv "certctl.io/certctl/internal/protocols/acme"
)

// --- a real HTTP-01 challenge web server -------------------------------------

// challengeServer serves the HTTP-01 key authorizations a client publishes, so
// the server's REAL HTTP01Validator can fetch and verify them — exactly as a CA
// validates a live web server.
type challengeServer struct {
	srv *httptest.Server
	mu  sync.Mutex
	ka  map[string]string // token -> key authorization
}

func newChallengeServer() *challengeServer {
	cs := &challengeServer{ka: map[string]string{}}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		val, ok := cs.ka[path.Base(r.URL.Path)]
		cs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(val))
	}))
	return cs
}

func (cs *challengeServer) publish(token, keyAuth string) {
	cs.mu.Lock()
	cs.ka[token] = keyAuth
	cs.mu.Unlock()
}

func (cs *challengeServer) Close() { cs.srv.Close() }

// httpClient routes every request to the challenge server regardless of host, so
// the in-process HTTP01Validator can "reach" the identifier's web server. This is
// the only seam — the validation logic that runs is the production one.
func (cs *challengeServer) httpClient() *http.Client {
	base, _ := url.Parse(cs.srv.URL)
	return &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		req.URL.Scheme = base.Scheme
		req.URL.Host = base.Host
		return http.DefaultTransport.RoundTrip(req)
	})}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func conformanceValidators(cs *challengeServer) acmesrv.Validators {
	// The production multiplexer, with only HTTP-01's network fetch routed to the
	// test challenge server.
	return acmesrv.Validators{
		HTTP01:    acmesrv.HTTP01Validator{Client: cs.httpClient()},
		DNS01:     acmesrv.DNS01Validator{},
		TLSALPN01: acmesrv.TLSALPN01Validator{},
	}
}

// --- full real-HTTP-01 issuance conformance ----------------------------------

// TestACMEConformanceRealHTTP01FullIssuance is R4.2's conformance acceptance: a
// real RFC 8555 client (golang.org/x/crypto/acme — the same protocol cert-manager
// speaks) registers, orders a multi-SAN certificate, and certctl validates the
// HTTP-01 challenge FOR REAL (the production HTTP01Validator fetches the published
// key authorization), then finalizes and issues. Unlike the older AcceptAll-based
// e2e, the real challenge-validation path is exercised end to end by a real
// client — the proxy for "cert-manager enrolls successfully."
func TestACMEConformanceRealHTTP01FullIssuance(t *testing.T) {
	builtin, err := ca.NewBuiltin("certctl ACME conformance CA")
	if err != nil {
		t.Fatal(err)
	}
	cs := newChallengeServer()
	t.Cleanup(cs.Close)
	ts := httptest.NewServer(acmesrv.New(builtin, conformanceValidators(cs)))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}

	domains := []string{"a.conformance.test", "b.conformance.test"}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domains...))
	if err != nil {
		t.Fatalf("new-order: %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			t.Fatalf("authz %s offered no http-01 challenge", authz.Identifier.Value)
		}
		// Publish the real key authorization so the server's validator fetches it.
		ka, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			t.Fatalf("compute http-01 response: %v", err)
		}
		cs.publish(chal.Token, ka)
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization (REAL http-01 validation) for %s: %v", authz.Identifier.Value, err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, domains[0], domains), true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	info, err := certinfo.Inspect(chainToPEM(der))
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	for _, d := range domains {
		found := false
		for _, n := range info.DNSNames {
			if n == d {
				found = true
			}
		}
		if !found {
			t.Errorf("issued cert SANs = %v, missing %q", info.DNSNames, d)
		}
	}
}

// TestACMEConformanceRejectsBadHTTP01 proves the validation is REAL: with a wrong
// published key authorization, the order does NOT become valid (the server fails
// the challenge closed) — the inverse of the happy path.
func TestACMEConformanceRejectsBadHTTP01(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	cs := newChallengeServer()
	t.Cleanup(cs.Close)
	ts := httptest.NewServer(acmesrv.New(builtin, conformanceValidators(cs)))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("bad.conformance.test"))
	if err != nil {
		t.Fatal(err)
	}
	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	var chal *xacme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
		}
	}
	cs.publish(chal.Token, "not-the-real-key-authorization") // wrong on purpose

	// The wrong key authorization must be rejected. certctl validates
	// synchronously, so the rejection can surface either at Accept (a 4xx) or, for
	// an async CA, when the authorization is polled — either way it must NOT
	// become valid.
	validated := false
	if _, err := client.Accept(ctx, chal); err == nil {
		if _, err := client.WaitAuthorization(ctx, order.AuthzURLs[0]); err == nil {
			validated = true
		}
	}
	if validated {
		t.Fatal("a wrong key authorization was accepted — HTTP-01 is not failing closed")
	}
}

// --- protocol differential (certctl vs a reference CA) -----------------------

// runACMEProtocolConformance drives a real client through the RFC 8555 protocol
// surface (directory → new-account → new-order → read authzs) and asserts it
// conforms: an order for N identifiers yields N pending authorizations whose
// identifiers match, each offering an http-01 challenge with a token. It does NOT
// complete validation, so it runs identically against certctl and a reference CA
// (Pebble) WITHOUT challenge-solving networking — that is the differential.
func runACMEProtocolConformance(t *testing.T, client *xacme.Client, ids []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(ids...))
	if err != nil {
		t.Fatalf("new-order: %v", err)
	}
	if len(order.AuthzURLs) != len(ids) {
		t.Fatalf("order returned %d authorizations, want %d", len(order.AuthzURLs), len(ids))
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			t.Fatalf("get authz: %v", err)
		}
		if authz.Identifier.Type != "dns" || !want[authz.Identifier.Value] {
			t.Errorf("authz identifier = %+v, not one of %v", authz.Identifier, ids)
		}
		if authz.Status != xacme.StatusPending {
			t.Errorf("authz %s status = %q, want pending", authz.Identifier.Value, authz.Status)
		}
		var http01 *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				http01 = c
			}
		}
		if http01 == nil || http01.Token == "" {
			t.Errorf("authz %s offers no usable http-01 challenge", authz.Identifier.Value)
		}
	}
}

// TestACMEProtocolConformsToReference runs the protocol-conformance routine
// against certctl — the SAME routine the CI Pebble differential runs against the
// reference CA, so any divergence in certctl's protocol surface from the RFC the
// reference also implements surfaces here.
func TestACMEProtocolConformsToReference(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.DefaultValidators()))
	t.Cleanup(ts.Close)
	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	runACMEProtocolConformance(t, client, []string{"x.conformance.test", "y.conformance.test"})
}

// TestACMEProtocolDifferentialVsPebble runs the IDENTICAL routine against the
// reference ACME CA (Pebble) when PEBBLE_DIRECTORY_URL is set — the differential.
// Skipped locally (no container runtime); runs in CI's acme-conformance job, with
// Pebble as a pinned service container and SSL_CERT_FILE pointing at Pebble's test
// CA so the default client trusts it (no crypto/tls in the test — AN-3).
func TestACMEProtocolDifferentialVsPebble(t *testing.T) {
	dir := os.Getenv("PEBBLE_DIRECTORY_URL")
	if dir == "" {
		t.Skip("PEBBLE_DIRECTORY_URL not set; the Pebble differential runs in CI (acme-conformance job)")
	}
	client, err := acmekey.NewRSAClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	runACMEProtocolConformance(t, client, []string{"a.pebble.test", "b.pebble.test"})
}
