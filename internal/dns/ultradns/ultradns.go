// Package ultradns is the Neustar/Vercara UltraDNS DNS-01 provider (S8b.10), built
// from the DNS-provider plugin template — the acme.DNSProvider interface plus the
// acme.ConformDNSProvider harness. It publishes and retracts the _acme-challenge TXT
// records the DNS-01 solver needs by calling UltraDNS's REST API over HTTPS, using a
// PUT upsert of the TXT rrset to present and a DELETE to clean up.
//
// Authentication is a caller-supplied OAuth2 bearer token, carried opaquely in an
// Authorization header. The token is never logged and is sealed at rest by the
// caller via the platform secret store (AN-8); error values built here never embed
// it. A provider does exactly two things — present and clean up a TXT record in one
// zone — and makes no other outbound calls; its capability grant is net.dial to the
// UltraDNS host only (the least-privilege pattern of the connector SDK, S5.5).
//
// Idempotency (AN-5): PresentTXT is a PUT upsert of the whole rrset, so re-presenting
// the same record is a no-op; CleanupTXT treats a 404 ("rrset not found") as success,
// so a retried cleanup never errors and never orphans records. When the solver runs
// inside the issuance path, that path provides the outbox delivery (AN-6).
//
// This package imports no crypto/* (AN-3): UltraDNS authenticates with a bearer token
// over TLS, so there is no client-side request signing to perform.
package ultradns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const txtTTL = 60

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials carry the OAuth2 bearer token UltraDNS authenticates with. The token
// is opaque to this package, never logged, and sealed at rest by the caller (AN-8).
type Credentials struct {
	BearerToken string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient,
// tests inject the in-memory double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is an UltraDNS DNS-01 provider bound to a single zone.
type Provider struct {
	zone     string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant
	creds    Credentials
	doer     HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the UltraDNS API endpoint (for tests or alternate
// regions/partitions).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns an UltraDNS provider that manages TXT records in zone, authenticating
// with creds. The endpoint defaults to the public UltraDNS API host.
func New(zone string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		zone:  zone,
		creds: creds,
		doer:  http.DefaultClient,
	}
	p.setEndpoint("https://api.ultradns.com")
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
func (p *Provider) Name() string { return "ultradns" }

// Capabilities declares the least privilege the provider needs: reach the UltraDNS
// endpoint over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes (or refreshes) the TXT record name=value via a PUT upsert of
// the rrset, which is idempotent: presenting the same record twice is a no-op (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	body, err := json.Marshal(rrset{TTL: txtTTL, RData: []string{quote(value)}})
	if err != nil {
		return fmt.Errorf("ultradns: encode rrset: %w", err)
	}
	req, err := p.newRequest(ctx, http.MethodPut, name, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.do(req, "present", name)
}

// CleanupTXT removes the TXT rrset for name via a DELETE. A 404 ("rrset not found")
// is treated as a no-op, so a retried cleanup never errors and never leaves the zone
// in an inconsistent state (AN-5).
func (p *Provider) CleanupTXT(ctx context.Context, name, _ string) error {
	req, err := p.newRequest(ctx, http.MethodDelete, name, nil)
	if err != nil {
		return err
	}
	if err := p.do(req, "cleanup", name); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusNotFound {
			return nil
		}
		return err
	}
	return nil
}

// newRequest builds an authenticated request to the TXT rrset path for name.
func (p *Provider) newRequest(ctx context.Context, method, name string, body io.Reader) (*http.Request, error) {
	path := "/zones/" + p.zone + "/rrsets/TXT/" + name
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.creds.BearerToken)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// do runs req through the shared cloudhttp round-trip (bounded read, non-2xx
// normalisation, drain; CODE-006) and maps a non-2xx response to an *apiError so
// CleanupTXT's 404-is-a-no-op predicate and the token-free error text (AN-8) are
// unchanged. UltraDNS returns no body the provider reads, so out is nil.
func (p *Provider) do(req *http.Request, action, name string) error {
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return fmt.Errorf("ultradns: %s %s: %w", action, name, err)
	}
	return nil
}

// quote wraps a TXT value in the double quotes UltraDNS stores its TXT rdata under.
func quote(v string) string { return "\"" + v + "\"" }

// rrset is the UltraDNS TXT rrset upsert body.
type rrset struct {
	TTL   int      `json:"ttl"`
	RData []string `json:"rdata"`
}

// apiError is a non-2xx UltraDNS response. Its body is the service error text and
// never carries the bearer token (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("ultradns: status %d: %s", e.status, e.body) }
