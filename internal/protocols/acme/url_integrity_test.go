// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/jose"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

type acmeURLMutation int

const (
	acmeURLMissing acmeURLMutation = iota
	acmeURLWrongPath
	acmeURLWrongAuthority
)

// acmeURLIntegrityTransport changes the HTTP request only after x/crypto/acme
// has signed its JWS. That produces the exact intermediary-confusion input RFC
// 8555 section 6.4 protects against: a real signature over one URL delivered to
// a different URL.
type acmeURLIntegrityTransport struct {
	base      http.RoundTripper
	mutation  acmeURLMutation
	actualURL string

	mu           sync.Mutex
	used         bool
	originalURL  string
	originalBody []byte
}

func (t *acmeURLIntegrityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	mutate := req.Method == http.MethodPost && !t.used
	if mutate {
		t.used = true
	}
	t.mu.Unlock()
	if !mutate {
		return t.transport().RoundTrip(req)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))

	t.mu.Lock()
	t.originalURL = req.URL.String()
	t.originalBody = bytes.Clone(body)
	t.mu.Unlock()

	switch t.mutation {
	case acmeURLMissing:
		body, err = acmeJWSWithoutProtectedURL(body)
		if err != nil {
			return nil, err
		}
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
	case acmeURLWrongPath:
		actual, err := url.Parse(t.actualURL)
		if err != nil {
			return nil, err
		}
		clone.URL.Path = actual.Path
		clone.URL.RawPath = actual.RawPath
		clone.URL.RawQuery = actual.RawQuery
	case acmeURLWrongAuthority:
		clone.Host = "wrong-authority.example"
	}
	return t.transport().RoundTrip(clone)
}

func (t *acmeURLIntegrityTransport) transport() http.RoundTripper {
	if t.base != nil {
		return t.base
	}
	return http.DefaultTransport
}

func (t *acmeURLIntegrityTransport) captured(tst *testing.T) (string, []byte) {
	tst.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.used || t.originalURL == "" || len(t.originalBody) == 0 {
		tst.Fatal("URL-integrity transport captured no signed ACME POST")
	}
	return t.originalURL, bytes.Clone(t.originalBody)
}

func acmeJWSWithoutProtectedURL(body []byte) ([]byte, error) {
	var flattened map[string]string
	if err := json.Unmarshal(body, &flattened); err != nil {
		return nil, err
	}
	protected, err := base64.RawURLEncoding.DecodeString(flattened["protected"])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(protected, &header); err != nil {
		return nil, err
	}
	delete(header, "url")
	protected, err = json.Marshal(header)
	if err != nil {
		return nil, err
	}
	flattened["protected"] = base64.RawURLEncoding.EncodeToString(protected)
	return json.Marshal(flattened)
}

func requireACMEUnauthorized(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("URL-mismatched ACME JWS succeeded, want unauthorized")
	}
	var problem *xacme.Error
	if !errors.As(err, &problem) {
		t.Fatalf("URL-mismatched ACME JWS error = %T %v, want *acme.Error", err, err)
	}
	if problem.StatusCode != http.StatusUnauthorized || !strings.HasSuffix(problem.ProblemType, ":unauthorized") {
		t.Fatalf("URL-mismatched ACME JWS problem = %+v, want HTTP 401 unauthorized", problem)
	}
}

func replayCapturedACMEJWS(t *testing.T, rawURL string, body []byte, wantStatus int) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("exact signed-JWS retry status = %d body=%s, want %d; URL mismatch consumed the nonce", resp.StatusCode, raw, wantStatus)
	}
}

// TestACMEOuterJWSURLIntegrityRejectsJWKBeforeNonceConsumption covers the
// account-key (jwk) form. Missing URL, path confusion, and authority confusion
// are unauthorized; the original byte-exact JWS then succeeds, proving the
// mismatch was refused before its nonce was consumed.
func TestACMEOuterJWSURLIntegrityRejectsJWKBeforeNonceConsumption(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutation   acmeURLMutation
		actualPath string
	}{
		{name: "missing protected url", mutation: acmeURLMissing},
		{name: "wrong path", mutation: acmeURLWrongPath, actualPath: "/acme/revoke-cert"},
		{name: "wrong authority", mutation: acmeURLWrongAuthority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builtin, err := ca.NewBuiltin("trstctl ACME URL-integrity CA")
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
			t.Cleanup(ts.Close)

			transport := &acmeURLIntegrityTransport{
				mutation:  tc.mutation,
				actualURL: ts.URL + tc.actualPath,
			}
			client, err := acmekey.NewRSAClient(ts.URL + "/directory")
			if err != nil {
				t.Fatal(err)
			}
			client.HTTPClient = &http.Client{Transport: transport}
			_, err = client.Register(t.Context(), &xacme.Account{}, xacme.AcceptTOS)
			requireACMEUnauthorized(t, err)

			originalURL, originalBody := transport.captured(t)
			message, err := jose.ParseACMEJWS(originalBody)
			if err != nil {
				t.Fatalf("parse captured stock-client JWS: %v", err)
			}
			if message.Protected.URL != originalURL || message.Protected.Nonce == "" || len(message.Protected.JWK) == 0 || message.Protected.Kid != "" {
				t.Fatalf("captured request is not exact jwk URL-bound form: protected=%+v request_url=%q", message.Protected, originalURL)
			}
			replayCapturedACMEJWS(t, originalURL, originalBody, http.StatusCreated)
		})
	}
}

// TestACMEOuterJWSURLIntegrityRejectsKidPOSTAsGETBeforeNonceConsumption covers
// the authenticated kid form and an empty-payload POST-as-GET. Routing a signed
// authorization read to the order URL must not expose the order resource.
func TestACMEOuterJWSURLIntegrityRejectsKidPOSTAsGETBeforeNonceConsumption(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME POST-as-GET URL-integrity CA")
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
		t.Fatalf("register stock client: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("url-integrity.acme.test"))
	if err != nil {
		t.Fatalf("create stock-client order: %v", err)
	}
	if len(order.AuthzURLs) != 1 {
		t.Fatalf("order authorization URLs = %v, want one", order.AuthzURLs)
	}

	transport := &acmeURLIntegrityTransport{
		mutation:  acmeURLWrongPath,
		actualURL: order.URI,
	}
	client.HTTPClient = &http.Client{Transport: transport}
	_, err = client.GetAuthorization(ctx, order.AuthzURLs[0])
	requireACMEUnauthorized(t, err)

	originalURL, originalBody := transport.captured(t)
	message, err := jose.ParseACMEJWS(originalBody)
	if err != nil {
		t.Fatalf("parse captured stock-client POST-as-GET JWS: %v", err)
	}
	if message.Protected.URL != originalURL || message.Protected.Kid == "" || len(message.Protected.JWK) != 0 || len(message.Payload) != 0 {
		t.Fatalf("captured request is not exact kid POST-as-GET form: protected=%+v payload_len=%d request_url=%q", message.Protected, len(message.Payload), originalURL)
	}
	replayCapturedACMEJWS(t, originalURL, originalBody, http.StatusOK)
}

// TestACMEOuterJWSURLIntegrityRejectsSchemeDifference makes the stock client
// sign the directory's HTTP URL, then uses the same authority over TLS. The JWS
// is cryptographically valid, but http and https are different exact strings.
func TestACMEOuterJWSURLIntegrityRejectsSchemeDifference(t *testing.T) {
	builtin, err := ca.NewBuiltin("trstctl ACME scheme-integrity CA")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(acmesrv.New(builtin, acmesrv.AcceptAll{}))
	t.Cleanup(ts.Close)
	transport := &acmeSchemeDifferenceTransport{base: ts.Client().Transport}
	directoryURL := "http://" + strings.TrimPrefix(ts.URL, "https://") + "/directory"
	client, err := acmekey.NewRSAClient(directoryURL)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{Transport: transport}
	_, err = client.Register(t.Context(), &xacme.Account{}, xacme.AcceptTOS)
	requireACMEUnauthorized(t, err)
	if !transport.sawSignedHTTPURL() {
		t.Fatal("scheme-difference transport did not deliver a stock-client JWS signed for http over the TLS request")
	}
}

type acmeSchemeDifferenceTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	saw  bool
}

func (t *acmeSchemeDifferenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "https"
	if req.Method == http.MethodPost {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.ContentLength = int64(len(body))
		message, err := jose.ParseACMEJWS(body)
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		t.saw = strings.HasPrefix(message.Protected.URL, "http://") && clone.URL.Scheme == "https"
		t.mu.Unlock()
	}
	resp, err := t.base.RoundTrip(clone)
	if err != nil || req.Method != http.MethodGet || req.URL.Path != "/directory" {
		return resp, err
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	httpsBase := "https://" + req.URL.Host
	httpBase := "http://" + req.URL.Host
	raw = bytes.ReplaceAll(raw, []byte(httpsBase), []byte(httpBase))
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	resp.ContentLength = int64(len(raw))
	resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	return resp, nil
}

func (t *acmeSchemeDifferenceTransport) sawSignedHTTPURL() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.saw
}
