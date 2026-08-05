// SPDX-License-Identifier: MPL-2.0

package enrollproxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/enrollproxy"
)

// The relay proxies enrolment and decides nothing (epic A4).
//
// The relay sits inside the customer's network — which is exactly where an
// attacker with a foothold already is. So the properties that matter are all
// about what this proxy does NOT do: it does not speak with its own identity, it
// does not interpret a protocol body, and it does not open a path to anything
// but the enrolment endpoints.

// upstream is a stand-in control plane that records what reached it.
type upstream struct {
	srv     *httptest.Server
	gotPath string
	gotAuth []string
	gotBody string
	gotHdrs http.Header
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.gotPath = r.URL.Path
		u.gotAuth = r.Header.Values("Authorization")
		u.gotHdrs = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		u.gotBody = string(body)
		w.Header().Set("Replay-Nonce", "upstream-nonce")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"valid"}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func newProxy(t *testing.T, up *upstream) *httptest.Server {
	t.Helper()
	client := up.srv.Client()
	p, err := enrollproxy.New(up.srv.URL, client)
	if err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv
}

// An enrolment request reaches the control plane unchanged.
func TestAnEnrolmentRequestReachesTheControlPlaneUnaltered(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	proxy := newProxy(t, up)

	body := `{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"e30","signature":"sig"}`
	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/acme/new-order", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if up.gotPath != "/acme/new-order" {
		t.Errorf("upstream saw path %q, want /acme/new-order", up.gotPath)
	}
	// The JWS body must arrive byte-identical: it is SIGNED, and a proxy that
	// reformatted it would invalidate every request it forwarded.
	if up.gotBody != body {
		t.Errorf("the signed body was altered in transit:\n got %q\nwant %q", up.gotBody, body)
	}
	if got := up.gotHdrs.Get("Content-Type"); got != "application/jose+json" {
		t.Errorf("content type = %q; a protocol client's content negotiation must survive", got)
	}
	// And the response comes back whole, including protocol headers a client
	// depends on.
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	if resp.Header.Get("Replay-Nonce") != "upstream-nonce" {
		t.Error("the ACME replay nonce did not survive the proxy; a client cannot make its " +
			"next request without it")
	}
}

// THE property: the relay does not speak with its own identity.
//
// The relay holds an mTLS credential the control plane trusts. If the proxy
// attached it, every device in the segment would enrol with the relay's
// authority — so a device that should only be able to request its own
// certificate could request any of them. A compromised sensor would become a CA
// client.
func TestTheProxyDoesNotAddItsOwnCredential(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	proxy := newProxy(t, up)

	// A client that presents NOTHING must arrive presenting nothing.
	resp, err := http.Get(proxy.URL + "/directory")
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	_ = resp.Body.Close()

	if len(up.gotAuth) != 0 {
		t.Fatalf("the proxy attached an Authorization header (%v) the client never sent; every "+
			"device in the segment would then enrol with the relay's authority", up.gotAuth)
	}
	for _, header := range []string{"X-Trstctl-Agent", "X-Agent-Identity", "Proxy-Authorization"} {
		if up.gotHdrs.Get(header) != "" {
			t.Errorf("the proxy asserted identity through %s", header)
		}
	}
}

// A client's own credential passes through untouched.
func TestAClientsOwnCredentialSurvives(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	proxy := newProxy(t, up)

	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/.well-known/est/cacerts", nil)
	req.Header.Set("Authorization", "Basic ZGV2aWNlOnBhc3M=")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if len(up.gotAuth) != 1 || up.gotAuth[0] != "Basic ZGV2aWNlOnBhc3M=" {
		t.Fatalf("the client's own credential did not reach the control plane: %v", up.gotAuth)
	}
}

// The proxy is not a tunnel to the API.
//
// A segment that could reach /api/v1 through a relay would hold the control
// plane's whole administrative surface — a far larger grant than "devices here
// can enrol", and one nobody would have knowingly given.
func TestTheProxyIsNotATunnelToTheAPI(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	proxy := newProxy(t, up)

	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/issuers",
		"/healthz",
		"/metrics",
		"/acme-but-not-really",
		"/../api/v1/certificates",
	} {
		resp, err := http.Get(proxy.URL + path)
		if err != nil {
			continue // a malformed path the client library refuses is also fine
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("path %q was proxied (status %d); the relay must forward enrolment "+
				"protocols and nothing else", path, resp.StatusCode)
		}
	}
	if up.gotPath != "" {
		t.Errorf("a non-protocol path reached the control plane: %q", up.gotPath)
	}
}

// A plaintext upstream is refused.
//
// The proxied traffic carries CSRs and, for SCEP, the challenge password. A
// plaintext hop would put both on a wire inside the network this relay exists
// because nobody trusts.
func TestAPlaintextUpstreamIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := enrollproxy.New("http://control-plane.internal", nil); err == nil {
		t.Fatal("a plaintext upstream was accepted")
	}
	if _, err := enrollproxy.New("https://", nil); err == nil {
		t.Fatal("an upstream naming no host was accepted")
	}
}

// Hop-by-hop headers are stripped in both directions.
func TestHopByHopHeadersAreStripped(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	proxy := newProxy(t, up)

	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/directory", nil)
	req.Header.Set("Proxy-Authorization", "Basic c25lYWt5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if up.gotHdrs.Get("Proxy-Authorization") != "" {
		t.Error("a hop-by-hop credential was forwarded upstream")
	}
}

// The paths this proxy serves are exactly the enrolment protocols.
func TestProxiedPathsAreTheEnrolmentProtocolsAndNothingElse(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/directory", "/acme/new-order", "/.well-known/est/simpleenroll",
		"/scep", "/scep?operation=PKIOperation", "/cmp",
	} {
		if !enrollproxy.Proxied(path) {
			t.Errorf("%q is an enrolment path and is not proxied", path)
		}
	}
	for _, path := range []string{
		"/api/v1/certificates", "/", "/healthz", "/metrics", "/ssh/", "/tsa",
	} {
		if enrollproxy.Proxied(path) {
			t.Errorf("%q is not an enrolment path and would be proxied", path)
		}
	}
}

// Killing the primary mid-flow: the client's next attempt succeeds (epic A4).
//
// The acceptance criterion. It works because the proxy is stateless — an ACME
// order lives in the control plane, not in a relay — so a client whose endpoint
// dies simply retries and the order is still there. Failover is a routing
// problem here rather than a replication one, and that was a design choice worth
// paying for.
func TestKillingThePrimaryEndpointLetsTheNextAttemptSucceed(t *testing.T) {
	t.Parallel()
	primary := newUpstream(t)
	secondary := newUpstream(t)

	pool, err := enrollproxy.NewPool(
		[]string{primary.srv.URL, secondary.srv.URL}, primary.srv.Client(), time.Second)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	front := httptest.NewServer(pool)
	defer front.Close()

	// The first request goes to the first endpoint and advances the rotation, so
	// the SECOND request is the one aimed at `secondary`. Killing that one is
	// what forces a real failover rather than letting round-robin happen to
	// pick a live endpoint — which is how this test passed for the wrong reason
	// until a mutation showed it did.
	resp, err := http.Get(front.URL + "/directory")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first request status = %d, want 201", resp.StatusCode)
	}
	if primary.gotPath != "/directory" {
		t.Fatalf("the rotation did not start where this test assumes; primary saw %q", primary.gotPath)
	}

	// The endpoint the next request is aimed at dies mid-flow.
	secondary.srv.Close()

	// The client simply tries again — which is what a certbot or sscep does —
	// and it must succeed, through the endpoint that is still there.
	resp, err = http.Get(front.URL + "/acme/new-order")
	if err != nil {
		t.Fatalf("request after the primary died: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("after losing an endpoint the client got %d (%s); a segment with two relays "+
			"must survive losing one, or the second one is decoration", resp.StatusCode, body)
	}
	if primary.gotPath != "/acme/new-order" {
		t.Errorf("the surviving endpoint never saw the failed-over request; it saw %q",
			primary.gotPath)
	}
	if h := pool.Health(); h.Unhealthy != 1 {
		t.Errorf("health reports %d unhealthy endpoints after one died, want 1", h.Unhealthy)
	}
}

// A 5xx FROM the control plane is an answer, not a reason to fail over.
//
// Retrying elsewhere would ask a second endpoint the same question, get the same
// refusal, and make a real error look like a flapping relay — while hiding the
// control plane's actual response from the client that needs to see it.
func TestAControlPlaneErrorIsNotTreatedAsAFailover(t *testing.T) {
	t.Parallel()
	refusing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:serverInternal"}`))
	}))
	defer refusing.Close()

	pool, err := enrollproxy.NewPool([]string{refusing.URL}, refusing.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(pool)
	defer front.Close()

	resp, err := http.Get(front.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d; the control plane's own error must reach the client rather than "+
			"being retried away", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "acme:error") {
		t.Errorf("the control plane's problem document did not reach the client: %s", body)
	}
	if h := pool.Health(); h.Unhealthy != 0 {
		t.Errorf("a control-plane error marked %d endpoints unhealthy; only a transport failure "+
			"should", h.Unhealthy)
	}
}

// Every endpoint down is reported as unavailable, not as a success.
func TestEveryEndpointDownIsReportedRatherThanHidden(t *testing.T) {
	t.Parallel()
	dead := newUpstream(t)
	url := dead.srv.URL
	client := dead.srv.Client()
	dead.srv.Close()

	pool, err := enrollproxy.NewPool([]string{url}, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(pool)
	defer front.Close()

	resp, err := http.Get(front.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when nothing is answering", resp.StatusCode)
	}
}

// A traversal path is cleaned BEFORE the allowlist sees it.
//
// "/acme/../api/v1/certificates" starts with a proxied prefix and resolves to
// one that is not. Relying on the outbound HTTP client to normalise it would
// make the confinement somebody else's property; cleaning first means the string
// the allowlist checks is the string that gets sent.
func TestATraversalPathIsCleanedBeforeTheAllowlistCheck(t *testing.T) {
	t.Parallel()
	up := newUpstream(t)
	p, err := enrollproxy.New(up.srv.URL, up.srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"/acme/../api/v1/certificates",
		"/.well-known/est/../../api/v1/issuers",
		"/scep/../../metrics",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://relay.local", nil)
		// Set the path directly: a normalising client would otherwise resolve
		// it before this handler ever saw it, which is the point.
		req.URL.Path = raw
		p.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("traversal path %q was proxied (status %d)", raw, rec.Code)
		}
	}
	if up.gotPath != "" {
		t.Errorf("a traversal path reached the control plane: %q", up.gotPath)
	}
}
