// Package ns1 is the NS1 (IBM NS1 Connect) DNS-01 provider (S8b.9), built from the
// DNS-provider plugin template — the acme.DNSProvider interface plus the
// acme.ConformDNSProvider harness, the same shape as the Route 53 reference provider
// (internal/dns/route53). It publishes and retracts the _acme-challenge TXT records
// the DNS-01 solver needs by calling the NS1 v1 records API over HTTPS, authenticated
// with an NS1 API key in the X-NSONE-Key header.
//
// A provider does exactly two things — present and clean up a TXT record in one
// zone — and makes no other outbound calls; its capability grant is net.dial to the
// NS1 API host only (the least-privilege pattern of the connector SDK, S5.5). The
// API key is carried as an opaque value, is never logged, and is sealed at rest by
// the caller via the platform secret store (AN-8). This package imports no crypto/*
// (AN-3): NS1 authenticates with a bearer-style header, so there is no client-side
// signing to route through the crypto boundary.
//
// Idempotency (AN-5): an NS1 record PUT is create-or-replace, so PresentTXT is an
// upsert and re-presenting the same record is a no-op; CleanupTXT treats a 404
// (record already gone) as success, so a retried cleanup never errors and never
// orphans records. When the solver runs inside the issuance path, that path provides
// the outbox delivery (AN-6).
package ns1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// defaultEndpoint is the public NS1 API base URL.
const defaultEndpoint = "https://api.nsone.net/v1"

// apiKeyHeader is the NS1 authentication header carrying the API key.
const apiKeyHeader = "X-NSONE-Key"

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials are the NS1 API credentials used to authenticate requests. The API key
// is opaque to this package, never logged, and sealed at rest by the caller (AN-8).
type Credentials struct {
	APIKey string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the in-process NS1 double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is an NS1 DNS-01 provider bound to a single zone.
type Provider struct {
	zone     string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant
	creds    Credentials
	doer     HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the NS1 API endpoint (for tests or a private NS1 Connect
// deployment).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the NS1 double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns an NS1 provider that manages TXT records in zone, authenticating with
// creds. The endpoint defaults to the public NS1 API host.
func New(zone string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		zone:  strings.TrimSuffix(zone, "."),
		creds: creds,
		doer:  http.DefaultClient,
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
func (p *Provider) Name() string { return "ns1" }

// Capabilities declares the least privilege the provider needs: reach the NS1 API
// host over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// recordURL is the NS1 records endpoint for the (zone, name) TXT record:
// {endpoint}/zones/{zone}/{name}/TXT.
func (p *Provider) recordURL(name string) string {
	domain := strings.TrimSuffix(name, ".")
	return p.endpoint + "/zones/" + p.zone + "/" + domain + "/TXT"
}

// PresentTXT publishes (or refreshes) the TXT record name=value via a PUT, which NS1
// treats as create-or-replace, so presenting the same record twice is a no-op
// (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	body, err := json.Marshal(recordBody{
		Answers: []answer{{Answer: []string{value}}},
	})
	if err != nil {
		return fmt.Errorf("ns1: encode record: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.recordURL(name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := p.do(req); err != nil {
		return fmt.Errorf("ns1: present %s: %w", name, err)
	}
	return nil
}

// CleanupTXT removes the TXT record for name via a DELETE. NS1 deletes the whole
// record set, and a 404 (the record is already gone) is treated as a no-op, so a
// retried cleanup never errors and never leaves the zone in an inconsistent state
// (AN-5). value is unused: NS1 addresses records by (zone, name, type).
func (p *Provider) CleanupTXT(ctx context.Context, name, _ string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.recordURL(name), nil)
	if err != nil {
		return err
	}
	if err := p.do(req); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("ns1: cleanup %s: %w", name, err)
	}
	return nil
}

// do sets the NS1 auth header on req and runs it through the shared cloudhttp
// round-trip (bounded read, non-2xx normalisation, drain; CODE-006). A non-2xx
// response is translated into an *apiError so CleanupTXT's 404-is-a-no-op predicate
// and the error text (which never carries the API key, AN-8) are unchanged. The NS1
// records API returns no body the provider reads, so out is nil.
func (p *Provider) do(req *http.Request) error {
	req.Header.Set(apiKeyHeader, p.creds.APIKey)
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return err
	}
	return nil
}

// recordBody is the NS1 records-API request body for a TXT record. Only the answers
// are sent; NS1 infers zone/domain/type from the request path.
type recordBody struct {
	Answers []answer `json:"answers"`
}

type answer struct {
	Answer []string `json:"answer"`
}

// apiError is a non-2xx NS1 response. Its body is the service error text and never
// carries the request API key (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("ns1: status %d: %s", e.status, e.body) }
