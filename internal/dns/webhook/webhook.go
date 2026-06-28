// Package webhook is the generic DNS-01 webhook provider. It lets operators wire
// providers outside the built-in catalog without giving trstctl a provider-specific
// client: PresentTXT POSTs a small JSON body to {endpoint}/present, CleanupTXT POSTs
// the same shape to {endpoint}/cleanup, and the remote endpoint owns the DNS API
// details. The bearer credential is held as []byte, never logged, and should be
// stored as a secret reference by callers (AN-8).
package webhook

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
	"trstctl.com/trstctl/internal/secrettext"
)

var _ acme.DNSProvider = (*Provider)(nil)

// Credentials carry the webhook bearer token. The token is opaque to this package,
// never logged, and stored as bytes so callers can wipe the source buffer (AN-8).
type Credentials struct {
	BearerToken []byte
}

// HTTPDoer is the minimal HTTP seam used by production and tests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider publishes DNS-01 records by calling an operator-owned webhook endpoint.
type Provider struct {
	endpoint string
	host     string
	creds    Credentials
	doer     HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient injects the HTTP doer.
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns a webhook provider bound to endpoint. endpoint is the base URL; the
// provider calls /present and /cleanup below it.
func New(endpoint string, creds Credentials, opts ...Option) *Provider {
	creds.BearerToken = secrettext.Clone(creds.BearerToken)
	p := &Provider{creds: creds, doer: http.DefaultClient}
	p.setEndpoint(endpoint)
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
func (p *Provider) Name() string { return "webhook" }

// Capabilities declares the one host the provider may call.
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT asks the webhook to publish name=value. The webhook contract requires
// the remote endpoint to treat duplicate present calls as success.
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	return p.post(ctx, "present", name, value)
}

// CleanupTXT asks the webhook to retract name=value. The webhook contract requires
// the remote endpoint to treat an already-absent record as success.
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	return p.post(ctx, "cleanup", name, value)
}

func (p *Provider) post(ctx context.Context, action, name, value string) error {
	body, err := json.Marshal(request{Action: action, Name: name, Value: value})
	if err != nil {
		return fmt.Errorf("webhookdns: encode %s: %w", action, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(p.creds.BearerToken) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", p.creds.BearerToken))
	}
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return fmt.Errorf("webhookdns: %s %s: %w", action, name, err)
	}
	return nil
}

type request struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("webhookdns: status %d: %s", e.status, e.body) }
