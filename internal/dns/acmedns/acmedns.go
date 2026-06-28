// Package acmedns is the acme-dns DNS-01 provider (S8b.12), built from the
// DNS-provider plugin template — the acme.DNSProvider interface that the DNS-01
// solver drives. acme-dns (https://github.com/joohoi/acme-dns) is a tiny purpose-
// built DNS server whose only job is to hold the single _acme-challenge TXT value
// for a delegated validation zone: you register an account once, point
// _acme-challenge.<your-domain> at <subdomain>.auth.acme-dns.io with a permanent
// CNAME, and thereafter publish each challenge value through acme-dns's two-field
// HTTP API instead of touching your real authoritative zone. This keeps the ACME
// credential's blast radius down to one throwaway TXT record and off your
// production DNS.
//
// This provider speaks that HTTP API: it authenticates with the account's
// X-Api-User / X-Api-Key headers and POSTs the challenge value to {endpoint}/update.
// acme-dns only ever stores the most-recent TXT for the subdomain — it ignores the
// record name entirely (the name is irrelevant because the real _acme-challenge.
// <domain> is a CNAME into acme-dns), so PresentTXT is naturally idempotent
// (re-POSTing the same value is a no-op) and CleanupTXT is a no-op: acme-dns has no
// delete endpoint, and the next challenge's update simply overwrites the value.
//
// Like every provider, it does exactly two things — present and clean up a TXT
// value — and makes no other outbound calls; its capability grant is net.dial to
// the acme-dns endpoint host only (the least-privilege pattern of the connector
// SDK, S5.5). The account credentials are carried as opaque fields, are never
// logged, and are sealed at rest by the caller via the platform secret store
// (AN-8). This package imports no crypto/* (AN-3): all transport TLS is the Go
// stdlib http.Client's, behind the HTTPDoer seam.
//
// RFC 2136 dynamic DNS UPDATE is served by internal/dns/rfc2136 for operators who
// want to publish directly into an authoritative zone. This acme-dns provider remains
// the lower-blast-radius delegated-zone path: it updates only the throwaway
// validation subdomain behind a one-time CNAME.
package acmedns

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

// defaultEndpoint is the public acme-dns instance run by the project. Operators who
// self-host acme-dns override it with WithEndpoint.
const defaultEndpoint = "https://auth.acme-dns.io"

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials are an acme-dns account's authentication pair: the username and the
// apikey ("password") returned at /register. They are opaque to this package, never
// logged, and sealed at rest by the caller (AN-8). The apikey is held as []byte,
// never a string, so it can be wiped and is not freely copied by the GC (AN-8); the
// username is a non-secret account label.
type Credentials struct {
	Username string // sent as X-Api-User
	Password []byte // the apikey, sent as X-Api-Key (AN-8: []byte, never logged)
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject an httptest-backed double.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is an acme-dns DNS-01 provider bound to a single acme-dns subdomain (the
// validation zone delegated for one account).
type Provider struct {
	subdomain string
	endpoint  string // base URL, no trailing slash
	host      string // host[:port] of endpoint, for the net.dial grant
	creds     Credentials
	doer      HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the acme-dns endpoint (for a self-hosted acme-dns instance
// or for tests). The default is the public auth.acme-dns.io.
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass an httptest double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns an acme-dns provider that publishes challenge values to the acme-dns
// account identified by subdomain, authenticating with creds. subdomain is the
// acme-dns subdomain registered for this account (the value /register returns and
// the CNAME target of the real _acme-challenge.<domain>). The endpoint defaults to
// the public acme-dns instance.
func New(subdomain string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		subdomain: subdomain,
		creds:     creds,
		doer:      http.DefaultClient,
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
func (p *Provider) Name() string { return "acmedns" }

// Capabilities declares the least privilege the provider needs: reach the acme-dns
// endpoint over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes value as the TXT for this acme-dns subdomain by POSTing to
// {endpoint}/update. acme-dns ignores name — it always holds the single most-recent
// TXT for the subdomain — so presenting is naturally idempotent: re-POSTing the same
// value is a no-op (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	return p.update(ctx, value)
}

// CleanupTXT is a no-op. acme-dns exposes no delete endpoint; the stored value is
// simply overwritten by the next challenge's update, so there is nothing to retract
// and a retried cleanup can never error or orphan a record (AN-5). The value left
// behind is a spent challenge digest for a throwaway validation zone, not anything
// sensitive.
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	return nil
}

// updateRequest is the acme-dns /update body. acme-dns reads only these two fields.
type updateRequest struct {
	SubDomain string `json:"subdomain"`
	Txt       string `json:"txt"`
}

func (p *Provider) update(ctx context.Context, value string) error {
	body, err := json.Marshal(updateRequest{SubDomain: p.subdomain, Txt: value})
	if err != nil {
		return fmt.Errorf("acmedns: encode update: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/update", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", p.creds.Username)
	// string(...) is the transient edge form of the []byte apikey on the wire
	// (AN-8); the long-lived secret stays []byte in the Credentials.
	req.Header.Set("X-Api-Key", string(p.creds.Password))

	// The shared cloudhttp round-trip owns the bounded read, non-2xx normalisation,
	// and drain (CODE-006); the non-2xx *StatusError is translated to the package's
	// *apiError, whose text is the acme-dns error body and never carries the request
	// credentials (AN-8). acme-dns's /update returns no body the provider reads, so
	// out is nil.
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return fmt.Errorf("acmedns: update %s: %w", p.subdomain, err)
	}
	return nil
}

// apiError is a non-2xx acme-dns response. Its body is the service error text (e.g.
// the {"error":"unauthorized"} acme-dns returns on a bad key) and never carries the
// request credentials (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("acmedns: status %d: %s", e.status, e.body) }
