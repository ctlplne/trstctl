// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

func buildCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func chainToPEM(der [][]byte) []byte {
	var out []byte
	for _, b := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return out
}

type acmeResponseRecord struct {
	method string
	path   string
	header http.Header
}

type acmeResponseRecorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	seen []acmeResponseRecord
}

func (r *acmeResponseRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.seen = append(r.seen, acmeResponseRecord{
		method: req.Method,
		path:   req.URL.Path,
		header: resp.Header.Clone(),
	})
	r.mu.Unlock()
	return resp, nil
}

func (r *acmeResponseRecorder) header(method, rawURL string) http.Header {
	u, err := url.Parse(rawURL)
	path := rawURL
	if err == nil {
		path = u.Path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.seen) - 1; i >= 0; i-- {
		if r.seen[i].method == method && r.seen[i].path == path {
			return r.seen[i].header.Clone()
		}
	}
	return nil
}

func assertRecordedLink(t *testing.T, rec *acmeResponseRecorder, method, rawURL, target, rel string) {
	t.Helper()
	h := rec.header(method, rawURL)
	if h == nil {
		t.Fatalf("no recorded ACME response for %s %s", method, rawURL)
	}
	if !hasLink(h, target, rel) {
		t.Fatalf("%s %s Link headers = %q, missing <%s>;rel=%q", method, rawURL, h.Values("Link"), target, rel)
	}
}

func hasLink(h http.Header, target, rel string) bool {
	want := "<" + target + ">;rel=\"" + rel + "\""
	for _, got := range h.Values("Link") {
		for _, part := range strings.Split(got, ",") {
			if strings.TrimSpace(part) == want {
				return true
			}
		}
	}
	return false
}

func TestACMEResourceResponsesAdvertiseLinkRelations(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME link relation CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	rec := &acmeResponseRecorder{}
	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{Transport: rec}

	ctx := context.Background()
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertRecordedLink(t, rec, http.MethodPost, ts.URL+"/acme/new-account", ts.URL+"/directory", "index")

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("links.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
	}
	assertRecordedLink(t, rec, http.MethodPost, ts.URL+"/acme/new-order", ts.URL+"/directory", "index")

	authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	assertRecordedLink(t, rec, http.MethodPost, authz.URI, ts.URL+"/directory", "index")

	var chal *xacme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			chal = c
		}
	}
	if chal == nil {
		t.Fatal("server offered no http-01 challenge")
	}
	if _, err := client.Accept(ctx, chal); err != nil {
		t.Fatalf("accept challenge: %v", err)
	}
	assertRecordedLink(t, rec, http.MethodPost, chal.URI, ts.URL+"/directory", "index")
	assertRecordedLink(t, rec, http.MethodPost, chal.URI, authz.URI, "up")
}

// TestACMEClientEnrollsEndToEnd is the acceptance proxy for "cert-manager enrolls
// successfully": a real RFC 8555 client (golang.org/x/crypto/acme) registers,
// orders, solves a challenge, and obtains a certificate from our server, which
// brokers issuance to the built-in CA.
func TestACMEClientEnrollsEndToEnd(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME built-in CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("svc.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
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
			t.Fatal("server offered no http-01 challenge")
		}
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

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, buildCSR(t, "svc.acme.test", []string{"svc.acme.test"}), true)
	if err != nil {
		t.Fatalf("finalize/create cert: %v", err)
	}
	info, err := certinfo.Inspect(chainToPEM(der))
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.acme.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.acme.test", info.DNSNames)
	}
}

func TestACMEFinalizeReplayReturnsOriginalOrder(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME replay CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	client, err := acmekey.NewRSAClient(ts.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("register: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("replay.acme.test"))
	if err != nil {
		t.Fatalf("authorize order: %v", err)
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
			t.Fatal("server offered no http-01 challenge")
		}
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

	csr := buildCSR(t, "replay.acme.test", []string{"replay.acme.test"})
	der, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("first finalize/create cert: %v", err)
	}
	replayDER, replayCertURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("replay finalize/create cert: %v", err)
	}
	if replayCertURL != certURL {
		t.Fatalf("replay certificate URL = %q, want original %q", replayCertURL, certURL)
	}
	if !bytes.Equal(chainToPEM(replayDER), chainToPEM(der)) {
		t.Fatal("replay finalize returned a different certificate chain")
	}
}

// TestRejectsUnknownNonce: a request carrying a nonce the server never issued is
// rejected as badNonce (anti-replay), without needing a valid signature.
func TestRejectsUnknownNonce(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)

	protected, _ := json.Marshal(map[string]any{
		"alg": "RS256", "kid": ts.URL + "/acme/acct/1",
		"nonce": "never-issued", "url": ts.URL + "/acme/new-order",
	})
	body, _ := json.Marshal(map[string]string{
		"protected": base64.RawURLEncoding.EncodeToString(protected),
		"payload":   "",
		"signature": base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature")),
	})
	resp, err := http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown-nonce request = %d, want 400", resp.StatusCode)
	}
	var problem struct{ Type string }
	_ = json.NewDecoder(resp.Body).Decode(&problem)
	if !strings.Contains(problem.Type, "badNonce") {
		t.Errorf("error type = %q, want badNonce", problem.Type)
	}
}

func TestRejectsOverLimitJWSBody(t *testing.T) {
	builtin, _ := ca.NewBuiltin("ca")
	srv := acmesrv.New(builtin, acmesrv.AcceptAll{})

	protected, _ := json.Marshal(map[string]any{
		"alg": "RS256", "kid": "https://ca.test/acme/acct/1",
		"nonce": "never-issued", "url": "https://ca.test/acme/new-order",
	})
	body, _ := json.Marshal(map[string]string{
		"protected": base64.RawURLEncoding.EncodeToString(protected),
		"payload":   "",
		"signature": base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature")),
	})
	if len(body) >= 1<<20 {
		t.Fatalf("test JWS body unexpectedly large: %d", len(body))
	}
	overLimit := append(append([]byte{}, body...), bytes.Repeat([]byte(" "), (1<<20)-len(body))...)
	overLimit = append(overLimit, 'x')

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/acme/new-order", bytes.NewReader(overLimit))
	req.Header.Set("Content-Type", "application/jose+json")
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit ACME JWS status %d, want 413", rec.Code)
	}
}
