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

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
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
// speaks) registers, orders a multi-SAN certificate, and trstctl validates the
// HTTP-01 challenge FOR REAL (the production HTTP01Validator fetches the published
// key authorization), then finalizes and issues. Unlike the older AcceptAll-based
// e2e, the real challenge-validation path is exercised end to end by a real
// client — the proxy for "cert-manager enrolls successfully."
func TestACMEConformanceRealHTTP01FullIssuance(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME conformance CA")
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

	// The wrong key authorization must be rejected. trstctl validates
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

// --- protocol differential (trstctl vs a reference CA) -----------------------

// runACMEProtocolConformance drives a real client through the RFC 8555 protocol
// surface (directory → new-account → new-order → read authzs) and asserts it
// conforms: an order for N identifiers yields N pending authorizations whose
// identifiers match, each offering an http-01 challenge with a token. It does NOT
// complete validation, so it runs identically against trstctl and a reference CA
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
// against trstctl — the SAME routine the CI Pebble differential runs against the
// reference CA, so any divergence in trstctl's protocol surface from the RFC the
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

// issueOneCert drives the real x/crypto/acme client through a full HTTP-01
// issuance against srv and returns the leaf DER. It is the shared setup for the
// revoke/keyChange round-trips (INTEROP-002).
func issueOneCert(t *testing.T, client *xacme.Client, cs *challengeServer, domain string) []byte {
	t.Helper()
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
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
		ka, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			t.Fatalf("http-01 response: %v", err)
		}
		cs.publish(chal.Token, ka)
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("accept challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("wait order: %v", err)
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, domain, []string{domain}), true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("issued an empty certificate chain")
	}
	return der[0]
}

// TestACMEDirectoryAdvertisesRevokeAndKeyChange is the INTEROP-002 directory
// acceptance: the ACME directory MUST advertise revokeCert (RFC 8555 §7.6) and
// keyChange (§7.1.1) so a conformant client can revoke a certificate and roll its
// account key. The real x/crypto/acme client surfaces these as RevokeURL and
// KeyChangeURL via Discover(); before the fix both were absent (empty), and a
// RevokeCert/AccountKeyRollover call had no URL to post to.
func TestACMEDirectoryAdvertisesRevokeAndKeyChange(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.DefaultValidators()))
	t.Cleanup(ts.Close)
	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover directory: %v", err)
	}
	if dir.RevokeURL == "" {
		t.Error("directory does not advertise revokeCert (RFC 8555 §7.6) — INTEROP-002")
	}
	if dir.KeyChangeURL == "" {
		t.Error("directory does not advertise keyChange (RFC 8555 §7.1.1) — INTEROP-002")
	}
}

// TestACMERevokeCertRoundTrips is the INTEROP-002 revocation acceptance: a real
// x/crypto/acme client issues a certificate, then revokes it via the ACME
// revokeCert endpoint (authorized by its account key, RFC 8555 §7.6), and the
// server records the certificate as revoked. Before the fix the directory had no
// revokeCert URL, so RevokeCert failed with "unsupported protocol scheme".
func TestACMERevokeCertRoundTrips(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	cs := newChallengeServer()
	t.Cleanup(cs.Close)
	srv := acmesrv.New(builtin, conformanceValidators(cs))
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	leaf := issueOneCert(t, client, cs, "revoke.conformance.test")

	fp, err := certinfo.Inspect(leaf)
	if err != nil {
		t.Fatalf("inspect leaf: %v", err)
	}
	if _, revoked := srv.IsRevoked(fp.SHA256Fingerprint); revoked {
		t.Fatal("certificate is revoked before any revoke request")
	}

	// Account-key revocation (key=nil => use the registered account key).
	if err := client.RevokeCert(ctx, nil, leaf, xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("RevokeCert (account-key path) failed — INTEROP-002: %v", err)
	}
	serial, revoked := srv.IsRevoked(fp.SHA256Fingerprint)
	if !revoked {
		t.Fatal("the server did not record the certificate as revoked after a successful RevokeCert")
	}
	if serial == "" {
		t.Error("revocation recorded an empty serial")
	}

	// A double revocation is a clean no-op for the client (the server returns
	// alreadyRevoked, which x/crypto/acme treats as success).
	if err := client.RevokeCert(ctx, nil, leaf, xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("second RevokeCert should be a no-op, got: %v", err)
	}
}

// TestACMERevokeRejectsUnauthorizedAccount proves revocation is AUTHORIZED, not a
// blanket allow (RFC 8555 §7.6): a DIFFERENT account (which did not order the
// certificate and does not hold its key) cannot revoke it — the server returns
// unauthorized and the certificate stays valid.
func TestACMERevokeRejectsUnauthorizedAccount(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	cs := newChallengeServer()
	t.Cleanup(cs.Close)
	srv := acmesrv.New(builtin, conformanceValidators(cs))
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ctx := context.Background()

	owner, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("owner register: %v", err)
	}
	leaf := issueOneCert(t, owner, cs, "owned.conformance.test")
	fp, _ := certinfo.Inspect(leaf)

	// A second, unrelated account.
	stranger, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("stranger register: %v", err)
	}
	// The stranger uses its own account key (key=nil) — it did not order the cert.
	if err := stranger.RevokeCert(ctx, nil, leaf, xacme.CRLReasonUnspecified); err == nil {
		t.Fatal("an unrelated account was allowed to revoke a certificate it does not own (RFC 8555 §7.6 authorization bypass)")
	}
	if _, revoked := srv.IsRevoked(fp.SHA256Fingerprint); revoked {
		t.Fatal("certificate was marked revoked by an unauthorized account")
	}
}

// TestACMEKeyChangeRollsOverAccountKey is the INTEROP-002 key-rollover acceptance:
// a real x/crypto/acme client rolls its account key via the keyChange endpoint
// (RFC 8555 §7.3.5), and the NEW key then authenticates a subsequent
// kid-authenticated request (a new order). Before the fix the directory had no
// keyChange URL, so AccountKeyRollover had nowhere to post.
func TestACMEKeyChangeRollsOverAccountKey(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.DefaultValidators()))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	// A pre-rollover order proves the old key works.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("before.rollover.test")); err != nil {
		t.Fatalf("pre-rollover order: %v", err)
	}

	newClient, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AccountKeyRollover(ctx, newClient.Key); err != nil {
		t.Fatalf("AccountKeyRollover failed — INTEROP-002: %v", err)
	}
	// After rollover, client.Key is the new key. A kid-authenticated request (a new
	// order) must now succeed under the rolled-over key — proving the server bound
	// the account to the new key.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("after.rollover.test")); err != nil {
		t.Fatalf("order after key rollover (new key must authenticate): %v", err)
	}
}

// TestACMEAcceptsECDSADefaultClientRegisters is the INTEROP-003 served-path
// acceptance: a stock client using its DEFAULT ECDSA P-256 account key (the
// certbot/acme.sh default — acmekey.NewClient generates ECDSA) registers and orders
// against the ACME server end to end. Before the fix the server rejected the EC
// account key at new-account with badPublicKey, so Register failed; now it succeeds
// and the same client can drive an order.
func TestACMEAcceptsECDSADefaultClientRegisters(t *testing.T) {
	builtin, err := ca.NewBuiltin("ca")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.DefaultValidators()))
	t.Cleanup(ts.Close)

	// acmekey.NewClient uses a freshly generated ECDSA P-256 account key (ES256),
	// exactly like an unmodified certbot/acme.sh.
	client, err := acmekey.NewClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("an ECDSA-account-key client could not register (INTEROP-003): %v", err)
	}
	// The same ECDSA-authenticated client can drive a kid-authenticated request.
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("ec.conformance.test"))
	if err != nil {
		t.Fatalf("ECDSA-account-key new-order: %v", err)
	}
	if len(order.AuthzURLs) != 1 {
		t.Fatalf("order returned %d authorizations, want 1", len(order.AuthzURLs))
	}
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
