// Package akamai is the Akamai Edge DNS DNS-01 provider (S8b.11), built from the
// DNS-provider plugin template — the acme.DNSProvider interface plus the
// acme.ConformDNSProvider harness, the same shape as the Route 53 reference provider
// (internal/dns/route53). It publishes and retracts the _acme-challenge TXT records
// the DNS-01 solver needs by calling Akamai's Edge DNS Zone Management API over
// HTTPS: a PUT upsert of the TXT record set to present, a DELETE to clean up.
//
// Authentication is Akamai EdgeGrid (EG1-HMAC-SHA256), the analogue of AWS SigV4:
// each request carries an Authorization header whose signature is a keyed MAC over a
// canonical "data to sign" string. Like the Route 53 signer, that keyed MAC and the
// request-body digest route through the crypto boundary (internal/crypto; AN-3) and
// this package imports no crypto/*. The EdgeGrid credentials (client token, client
// secret, access token) are carried as opaque values, are never logged, and are
// sealed at rest by the caller via the platform secret store (AN-8); error values
// built here never embed them.
//
// A provider does exactly two things — present and clean up a TXT record in one
// zone — and makes no other outbound calls; its capability grant is net.dial to the
// Akamai API host only (the least-privilege pattern of the connector SDK, S5.5).
//
// Idempotency (AN-5): PresentTXT is a PUT upsert of the whole record set, so
// re-presenting the same record is a no-op; CleanupTXT treats a 404 (the record set
// is already gone) as success, so a retried cleanup never errors and never orphans
// records. When the solver runs inside the issuance path, that path provides the
// outbox delivery (AN-6).
package akamai

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	// txtTTL is the TTL applied to published challenge records. DNS-01 records are
	// short-lived, so a low TTL keeps stale answers from lingering after cleanup.
	txtTTL = 60

	// authScheme is the EdgeGrid signing scheme name, used both as the Authorization
	// header prefix and as the first field of the data-to-sign string.
	authScheme = "EG1-HMAC-SHA256"

	// edgeGridTimeFormat is the EdgeGrid timestamp layout: "yyyyMMddTHH:mm:ss+0000",
	// always in UTC.
	edgeGridTimeFormat = "20060102T15:04:05+0000"

	// defaultEndpoint is a placeholder Akamai API base. EdgeGrid hosts are
	// account-specific (akab-<id>.luna.akamaiapis.net), so callers must override this
	// with WithEndpoint in practice; the default exists only so New never panics.
	defaultEndpoint = "https://akab-xxxx.luna.akamaiapis.net"
)

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials are the Akamai EdgeGrid credentials used to sign requests. All three
// are opaque to this package, never logged, and sealed at rest by the caller (AN-8).
// The API host is not part of the credentials — it comes from the endpoint.
type Credentials struct {
	ClientToken  string
	ClientSecret string
	AccessToken  string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the in-process Akamai double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is an Akamai Edge DNS DNS-01 provider bound to a single zone.
type Provider struct {
	zone     string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant and EdgeGrid host field
	creds    Credentials
	doer     HTTPDoer

	now   func() time.Time // injectable clock for deterministic EdgeGrid timestamps
	nonce func() string    // injectable nonce source for deterministic EdgeGrid nonces
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the Akamai API endpoint. EdgeGrid hosts are
// account-specific, so this is required in practice (the default is a placeholder).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the Akamai double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// WithNonce injects the per-request nonce source. Production uses a random nonce;
// tests inject a fixed value so the client and a verifying double agree
// deterministically.
func WithNonce(fn func() string) Option {
	return func(p *Provider) { p.nonce = fn }
}

// WithClock injects the timestamp source. Production uses time.Now; tests inject a
// fixed clock so the EdgeGrid timestamp (which is part of both the signing key and
// the data to sign) is deterministic.
func WithClock(fn func() time.Time) Option {
	return func(p *Provider) { p.now = fn }
}

// New returns an Akamai Edge DNS provider that manages TXT records in zone, signing
// requests with EdgeGrid credentials creds. The endpoint defaults to a placeholder
// and should be set with WithEndpoint.
func New(zone string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		zone:  strings.TrimSuffix(zone, "."),
		creds: creds,
		doer:  http.DefaultClient,
		now:   time.Now,
		nonce: defaultNonce,
	}
	p.setEndpoint(defaultEndpoint)
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Provider) setEndpoint(endpoint string) {
	p.endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		p.host = u.Host
	}
}

// Name identifies the provider.
func (p *Provider) Name() string { return "akamai" }

// Capabilities declares the least privilege the provider needs: reach the Akamai API
// host over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// recordPath is the Edge DNS Zone Management API path for the (zone, name) TXT
// record set: /config-dns/v2/zones/{zone}/names/{name}/types/TXT.
func (p *Provider) recordPath(name string) string {
	domain := strings.TrimSuffix(name, ".")
	return "/config-dns/v2/zones/" + p.zone + "/names/" + domain + "/types/TXT"
}

// PresentTXT publishes (or refreshes) the TXT record name=value via a PUT, which
// Akamai treats as create-or-replace for the record set, so presenting the same
// record twice is a no-op (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	body, err := json.Marshal(recordBody{
		Name:  strings.TrimSuffix(name, "."),
		Type:  "TXT",
		TTL:   txtTTL,
		RData: []string{quote(value)},
	})
	if err != nil {
		return fmt.Errorf("akamai: encode record: %w", err)
	}
	req, err := p.newRequest(ctx, http.MethodPut, name, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.do(req, body, "present", name)
}

// CleanupTXT removes the TXT record set for name via a DELETE. A 404 (the record set
// is already gone) is treated as a no-op, so a retried cleanup never errors and never
// leaves the zone in an inconsistent state (AN-5). value is unused: Akamai addresses
// the record set by (zone, name, type).
func (p *Provider) CleanupTXT(ctx context.Context, name, _ string) error {
	req, err := p.newRequest(ctx, http.MethodDelete, name, nil)
	if err != nil {
		return err
	}
	if err := p.do(req, nil, "cleanup", name); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusNotFound {
			return nil
		}
		return err
	}
	return nil
}

// newRequest builds an unsigned request to the TXT record-set path for name. The
// EdgeGrid Authorization header is attached later, just before the request is sent,
// by the cloudhttp signer in do() (so the signature covers exactly the bytes sent).
func (p *Provider) newRequest(ctx context.Context, method, name string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+p.recordPath(name), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// signEdgeGrid adds the EdgeGrid (EG1-HMAC-SHA256) Authorization header to req over
// body, using timestamp t and the given nonce. The digest and the keyed MAC route
// through the crypto boundary (AN-3).
//
// The construction (Akamai's published EdgeGrid algorithm):
//
//	timestamp = t.Format("20060102T15:04:05+0000")  // UTC
//	authData  = "EG1-HMAC-SHA256 client_token=<ct>;access_token=<at>;timestamp=<ts>;nonce=<n>;signature="
//	dataToSign = method \t scheme \t host \t relativeURL \t canonicalHeaders \t contentHash \t authData
//	  where scheme = "https", canonicalHeaders = "" (no signed headers),
//	  contentHash = base64(SHA256(body)) for POST/PUT else ""
//	signingKey = base64( HMAC-SHA256(key=clientSecret, data=timestamp) )
//	signature  = base64( HMAC-SHA256(key=signingKey,   data=dataToSign) )
//	Authorization = authData + signature
func (p *Provider) signEdgeGrid(req *http.Request, body []byte, t time.Time, nonce string) {
	timestamp := t.Format(edgeGridTimeFormat)
	authData := edgeGridAuthData(p.creds.ClientToken, p.creds.AccessToken, timestamp, nonce)
	dataToSign := edgeGridDataToSign(req.Method, p.host, edgeGridRelativeURL(req.URL), body, authData)
	signature := edgeGridSign(p.creds.ClientSecret, timestamp, dataToSign)
	req.Header.Set("Authorization", authData+signature)
}

// --- EdgeGrid signing primitives -------------------------------------------------
//
// These are factored into small pure functions, deliberately self-contained, so a
// verifying test double can reconstruct the exact same data-to-sign and signature
// from a received request. Keep this logic and any double's logic identical, or they
// will disagree and every request will 401 (the Route 53 / r53test discipline).

// edgeGridAuthData builds the "auth-data" prefix of the Authorization header. It is
// also the final field of the data-to-sign string and INCLUDES the trailing
// "signature=" (with an empty value): the signature is computed over everything up
// to and including that marker, then appended after it.
func edgeGridAuthData(clientToken, accessToken, timestamp, nonce string) string {
	return authScheme + " " +
		"client_token=" + clientToken + ";" +
		"access_token=" + accessToken + ";" +
		"timestamp=" + timestamp + ";" +
		"nonce=" + nonce + ";" +
		"signature="
}

// edgeGridRelativeURL returns the path+query portion of u that EdgeGrid signs.
func edgeGridRelativeURL(u *url.URL) string {
	rel := u.EscapedPath()
	if u.RawQuery != "" {
		rel += "?" + u.RawQuery
	}
	return rel
}

// edgeGridContentHash returns the base64(SHA256(body)) content hash EdgeGrid signs
// for a request that carries a body (POST/PUT); for any other method it is empty.
func edgeGridContentHash(method string, body []byte) string {
	if method != http.MethodPost && method != http.MethodPut {
		return ""
	}
	return base64.StdEncoding.EncodeToString(crypto.SHA256Sum(body))
}

// edgeGridDataToSign assembles the tab-joined data-to-sign string. The canonicalized
// headers field is empty because the provider signs no request headers.
func edgeGridDataToSign(method, host, relativeURL string, body []byte, authData string) string {
	return strings.Join([]string{
		method,
		"https", // scheme
		host,
		relativeURL,
		"", // canonicalized headers: no signed headers
		edgeGridContentHash(method, body),
		authData,
	}, "\t")
}

// edgeGridSigningKey derives the EdgeGrid signing key:
// base64( HMAC-SHA256(key=clientSecret, data=timestamp) ).
func edgeGridSigningKey(clientSecret, timestamp string) string {
	return base64.StdEncoding.EncodeToString(
		crypto.HMACSHA256([]byte(clientSecret), []byte(timestamp)))
}

// edgeGridSign computes the request signature:
// base64( HMAC-SHA256(key=signingKey, data=dataToSign) ), where signingKey is the
// base64 string from edgeGridSigningKey used as the HMAC key bytes.
func edgeGridSign(clientSecret, timestamp, dataToSign string) string {
	signingKey := edgeGridSigningKey(clientSecret, timestamp)
	return base64.StdEncoding.EncodeToString(
		crypto.HMACSHA256([]byte(signingKey), []byte(dataToSign)))
}

// do signs req with EdgeGrid and runs it through the shared cloudhttp round-trip
// (bounded read, non-2xx normalisation, drain; CODE-006). EdgeGrid signing stays here
// — supplied as a cloudhttp request-signer so its keyed MAC and content digest remain
// in this package behind the crypto boundary (AN-3) — and is applied just before the
// request is sent, over exactly the body bytes that will be transmitted. A non-2xx
// *StatusError is translated to the package's *apiError so CleanupTXT's 404-is-a-no-op
// predicate and the credential-free error text (AN-8) are unchanged. Akamai returns no
// body the provider reads, so out is nil.
func (p *Provider) do(req *http.Request, body []byte, action, name string) error {
	signer := func(r *http.Request, _ []byte) error {
		p.signEdgeGrid(r, body, p.now().UTC(), p.nonce())
		return nil
	}
	if err := cloudhttp.JSON(p.doer, req, nil, cloudhttp.WithSigner(signer)); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return fmt.Errorf("akamai: %s %s: %w", action, name, err)
	}
	return nil
}

// defaultNonce is the production nonce source: a fresh random token per request.
// EdgeGrid only requires the nonce be unique per request; the randomness is drawn
// through the crypto boundary so crypto/* stays out of this package (AN-3). A failure
// to read randomness yields an empty nonce, which the signature still covers — the
// request would simply be rejected by Akamai rather than sent with a guessable nonce.
func defaultNonce() string {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// quote wraps a TXT value in the double quotes Akamai stores its TXT rdata under.
func quote(v string) string { return "\"" + v + "\"" }

// recordBody is the Akamai Edge DNS record-set upsert body for a TXT record.
type recordBody struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	TTL   int      `json:"ttl"`
	RData []string `json:"rdata"`
}

// apiError is a non-2xx Akamai response. Its body is the service error text and never
// carries the request credentials (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("akamai: status %d: %s", e.status, e.body) }
