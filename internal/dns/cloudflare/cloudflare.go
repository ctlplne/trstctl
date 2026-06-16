// Package cloudflare is the Cloudflare DNS-01 provider (S8b.6), built from the same
// plugin template as the Route 53 reference provider (internal/dns/route53): the
// acme.DNSProvider interface plus the acme.ConformDNSProvider harness. It publishes
// and retracts the _acme-challenge TXT records the DNS-01 solver needs by calling the
// Cloudflare DNS Records API over HTTPS, authenticated with a scoped API token.
//
// Unlike Route 53 (which signs each request with AWS SigV4), Cloudflare authenticates
// with a bearer token sent in the Authorization header. The token is carried as an
// opaque string, is never logged, and is sealed at rest by the caller via the
// platform secret store (AN-8); error text returned to callers is the API response
// body, which never echoes the token. No cryptographic operation happens in this
// package, so it imports no crypto/* (AN-3) — there is nothing to route through the
// crypto boundary here.
//
// A provider does exactly two things — present and clean up a TXT record in one zone —
// and makes no other outbound calls; its capability grant is net.dial to the
// Cloudflare API host only (the least-privilege pattern of the connector SDK, S5.5).
//
// Idempotency (AN-5): PresentTXT first lists the record and returns early if it
// already exists, so re-presenting the same record is a no-op; CleanupTXT lists then
// deletes by id and treats "no matching record" as success, so a retried cleanup
// never errors and never orphans records. When the solver runs inside the issuance
// path, that path provides the outbox delivery (AN-6).
package cloudflare

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

const (
	defaultEndpoint = "https://api.cloudflare.com/client/v4"
	txtTTL          = 60
)

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials is the Cloudflare API token used to authenticate requests. The token is
// opaque to this package, never logged, and sealed at rest by the caller (AN-8).
type Credentials struct {
	APIToken string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is a Cloudflare DNS-01 provider bound to a single zone.
type Provider struct {
	zoneID   string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant
	creds    Credentials
	doer     HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the Cloudflare API endpoint (for tests or alternate
// gateways).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns a Cloudflare provider that manages TXT records in zoneID, authenticating
// with creds. The endpoint defaults to the public Cloudflare API host.
func New(zoneID string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		zoneID: zoneID,
		creds:  creds,
		doer:   http.DefaultClient,
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
func (p *Provider) Name() string { return "cloudflare" }

// Capabilities declares the least privilege the provider needs: reach the Cloudflare
// API host over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes the TXT record name=value. It first lists the zone for an
// existing record with the same name and content and returns early if one is found, so
// presenting the same record twice is a no-op (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	existing, err := p.list(ctx, name, value)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	body, err := json.Marshal(txtRecord{
		Type:    "TXT",
		Name:    name,
		Content: value,
		TTL:     txtTTL,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: encode record: %w", err)
	}
	path := "/zones/" + p.zoneID + "/dns_records"
	if err := p.do(ctx, http.MethodPost, path, body, nil); err != nil {
		return fmt.Errorf("cloudflare: create %s: %w", name, err)
	}
	return nil
}

// CleanupTXT removes the TXT record name=value: it lists the matching records and
// deletes each by id. A record that is already gone yields an empty list, so a retried
// cleanup is a no-op that never errors and never leaves the zone inconsistent (AN-5).
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	existing, err := p.list(ctx, name, value)
	if err != nil {
		return err
	}
	for _, rec := range existing {
		path := "/zones/" + p.zoneID + "/dns_records/" + rec.ID
		if err := p.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
			return fmt.Errorf("cloudflare: delete %s: %w", rec.ID, err)
		}
	}
	return nil
}

// list returns the TXT records in the zone matching name and content.
func (p *Provider) list(ctx context.Context, name, value string) ([]txtRecord, error) {
	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name", name)
	q.Set("content", value)
	path := "/zones/" + p.zoneID + "/dns_records?" + q.Encode()

	var lr listResponse
	if err := p.do(ctx, http.MethodGet, path, nil, &lr); err != nil {
		return nil, fmt.Errorf("cloudflare: list %s: %w", name, err)
	}
	return lr.Result, nil
}

// do issues an authenticated request to endpoint+path and, on a 2xx, decodes the JSON
// response into out (out may be nil to drain it). The bearer token is attached here
// and nowhere else; it is never written to logs or error text (AN-8). The round-trip
// — bounded read, non-2xx normalisation, JSON decode/drain — is the shared
// internal/cloudhttp (CODE-006); a non-2xx *StatusError is translated to the package's
// *apiError so the "cloudflare: status N: body" contract is unchanged.
func (p *Provider) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.creds.APIToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := cloudhttp.JSON(p.doer, req, out); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return err
	}
	return nil
}

// txtRecord is a Cloudflare DNS TXT record. Content is the raw authorization value
// (Cloudflare does not quote TXT content the way Route 53 does).
type txtRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// listResponse is the envelope Cloudflare wraps list results in.
type listResponse struct {
	Result []txtRecord `json:"result"`
}

// apiError is a non-2xx Cloudflare response. Its body is the API error text and never
// carries the request token (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("cloudflare: status %d: %s", e.status, e.body)
}
