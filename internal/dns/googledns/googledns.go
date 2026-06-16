// Package googledns is the Google Cloud DNS DNS-01 provider (S8b.8), built from the
// DNS-provider plugin template — the acme.DNSProvider interface plus the
// acme.ConformDNSProvider harness, the same template the Route 53 reference provider
// (internal/dns/route53, S8b.1) was cut from. It publishes and retracts the
// _acme-challenge TXT records the DNS-01 solver needs by posting Change resources to
// the Cloud DNS API's managedZones/{zone}/changes endpoint over HTTPS: a record is
// added via a Change with `additions` and removed via a Change with `deletions`.
//
// Authentication is a bearer OAuth2 access token supplied by the caller (the platform
// resolves the service-account flow upstream; this package does not implement the
// OAuth dance). The token is carried as an opaque string, is never logged, and is
// sealed at rest by the caller via the platform secret store (AN-8). A provider does
// exactly two things — present and clean up a TXT record in one managed zone — and
// makes no other outbound calls; its capability grant is net.dial to the Cloud DNS
// host only (the least-privilege pattern of the connector SDK, S5.5). This package
// imports no crypto/* (AN-3): a bearer token needs no request signing, so there is no
// crypto here at all.
//
// Idempotency (AN-5): Cloud DNS rejects adding a record that already exists and
// deleting one that is gone. PresentTXT treats an "already exists" rejection as a
// no-op success, so re-presenting the same record never errors; CleanupTXT treats a
// "not found" rejection as a no-op success, so a retried cleanup never errors and
// never orphans records. When the solver runs inside the issuance path, that path
// provides the outbox delivery (AN-6).
package googledns

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

// defaultEndpoint is the public Cloud DNS API base URL (v1).
const defaultEndpoint = "https://dns.googleapis.com/dns/v1"

// txtTTL is the TTL, in seconds, of the validation records. They live only for the
// length of a challenge, so a short TTL keeps cleanup fast.
const txtTTL = 60

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials carry the OAuth2 access token used as a bearer credential against the
// Cloud DNS API. The token is opaque to this package, never logged, and sealed at
// rest by the caller (AN-8). The caller is responsible for obtaining and refreshing
// it; this package does not implement the OAuth flow.
type Credentials struct {
	BearerToken string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the in-package double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is a Cloud DNS DNS-01 provider bound to a single project and managed zone.
type Provider struct {
	project  string
	zone     string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant
	creds    Credentials
	doer     HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the Cloud DNS API endpoint (for tests or a private service
// endpoint).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the in-package double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns a Cloud DNS provider that manages TXT records in the managed zone zone
// of project project, authenticating with creds. The endpoint defaults to the public
// Cloud DNS API.
func New(project, zone string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		project: project,
		zone:    zone,
		creds:   creds,
		doer:    http.DefaultClient,
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
func (p *Provider) Name() string { return "googledns" }

// Capabilities declares the least privilege the provider needs: reach the Cloud DNS
// endpoint over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes the TXT record name=value by posting a Change with the record
// in `additions`. Cloud DNS rejects adding a record that already exists; that
// rejection is treated as a no-op so re-presenting the same record is idempotent
// (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	rrset := p.rrset(name, value)
	if err := p.change(ctx, changeBody{Additions: []resourceRecordSet{rrset}}); err != nil {
		if isAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// CleanupTXT removes the TXT record name=value by posting a Change with the record in
// `deletions`. Cloud DNS rejects deleting a record that is already gone; that
// rejection is treated as a no-op, so a retried cleanup never errors and never leaves
// the zone in an inconsistent state (AN-5).
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	rrset := p.rrset(name, value)
	if err := p.change(ctx, changeBody{Deletions: []resourceRecordSet{rrset}}); err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// rrset builds the Cloud DNS resource-record set for a validation TXT record: an
// absolute (trailing-dot) name and a quoted rrdata, the wire forms Cloud DNS uses.
func (p *Provider) rrset(name, value string) resourceRecordSet {
	return resourceRecordSet{
		Name:    fqdn(name),
		Type:    "TXT",
		TTL:     txtTTL,
		RRDatas: []string{quote(value)},
	}
}

func (p *Provider) change(ctx context.Context, body changeBody) error {
	enc, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("googledns: encode change: %w", err)
	}

	endpoint := p.endpoint + "/projects/" + p.project + "/managedZones/" + p.zone + "/changes"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(enc))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.creds.BearerToken)

	// The shared cloudhttp round-trip owns the bounded read, non-2xx normalisation,
	// and drain (CODE-006); the non-2xx *StatusError is translated to the package's
	// *apiError so the is4xxContaining "already exists"/"not found" idempotency
	// predicates (and the token-free error text, AN-8) are unchanged. Cloud DNS
	// returns no body the provider reads, so out is nil.
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return fmt.Errorf("googledns: change: %w", err)
	}
	return nil
}

// fqdn returns name with exactly one trailing dot, the absolute form Cloud DNS stores
// record names under.
func fqdn(name string) string { return strings.TrimRight(name, ".") + "." }

// quote wraps a TXT value in the double quotes Cloud DNS stores rrdatas under.
func quote(v string) string { return "\"" + v + "\"" }

// changeBody is the Cloud DNS Change request body: a set of rrsets to add and a set
// to remove, applied atomically.
type changeBody struct {
	Additions []resourceRecordSet `json:"additions,omitempty"`
	Deletions []resourceRecordSet `json:"deletions,omitempty"`
}

// resourceRecordSet is a Cloud DNS rrset: an absolute name, a type, a TTL, and the
// (quoted, for TXT) rrdatas.
type resourceRecordSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

// apiError is a non-2xx Cloud DNS response. Its body is the service error text and
// never carries the bearer token (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("googledns: status %d: %s", e.status, e.body) }

// isAlreadyExists reports whether err is Cloud DNS's "already exists" rejection,
// returned when adding a record that is already present — a no-op for present.
func isAlreadyExists(err error) bool {
	return is4xxContaining(err, "alreadyexists", "already exists")
}

// isNotFound reports whether err is Cloud DNS's "not found" rejection, returned when
// deleting a record that is already gone — a no-op for cleanup.
func isNotFound(err error) bool {
	return is4xxContaining(err, "notfound", "not found")
}

// is4xxContaining reports whether err is an apiError with a 4xx status whose body
// (case-folded) contains any of the given needles.
func is4xxContaining(err error, needles ...string) bool {
	var ae *apiError
	if !errors.As(err, &ae) || ae.status/100 != 4 {
		return false
	}
	b := strings.ToLower(ae.body)
	for _, n := range needles {
		if strings.Contains(b, n) {
			return true
		}
	}
	return false
}
