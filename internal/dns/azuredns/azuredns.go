// Package azuredns is the Azure DNS DNS-01 provider (S8b.7), built from the
// DNS-provider plugin template the Route 53 reference (S8b.1) established — the
// acme.DNSProvider interface plus the acme.ConformDNSProvider harness. It publishes
// and retracts the _acme-challenge TXT records the DNS-01 solver needs by calling the
// Azure DNS resource-management API over HTTPS: a PUT to the record set's resource
// URL to present (an idempotent upsert) and a DELETE to clean up.
//
// Authentication is an Azure Active Directory (AAD) OAuth 2.0 bearer access token
// supplied by the caller — this package does not run the OAuth client-credentials
// flow; it only attaches the token as `Authorization: Bearer <token>` on every
// request. The token is carried opaquely, is never logged, and is sealed at rest by
// the caller via the platform secret store (AN-8). No crypto/* is imported (AN-3):
// the provider performs no cryptography of its own — TLS is handled by the injected
// HTTP client.
//
// A provider does exactly two things — present and clean up a TXT record in one DNS
// zone — and makes no other outbound calls; its capability grant is net.dial to the
// Azure management host only (the least-privilege pattern of the connector SDK,
// S5.5).
//
// Idempotency (AN-5): PresentTXT is a PUT upsert, so re-presenting the same record is
// a no-op; CleanupTXT treats a 404 (record set already gone) as success, so a retried
// cleanup never errors and never orphans records. When the solver runs inside the
// issuance path, that path provides the outbox delivery (AN-6).
package azuredns

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
	// apiVersion is the Azure DNS resource-management API version this provider
	// targets. It is carried as the api-version query parameter on every request.
	apiVersion = "2018-05-01"
	// txtTTL is the TTL (seconds) of the published _acme-challenge TXT record. It is
	// short because the record is transient — created for one validation and removed.
	txtTTL = 60
	// defaultEndpoint is the public Azure Resource Manager endpoint. WithEndpoint
	// overrides it for tests or for the sovereign clouds (US Gov, China, Germany).
	defaultEndpoint = "https://management.azure.com"
)

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials carry the AAD OAuth 2.0 bearer access token used to authorize Azure
// DNS requests. The caller obtains it (client-credentials, managed identity, or a
// federated token) and supplies it here; this package only presents it. BearerToken
// is opaque to this package, is never logged, and is sealed at rest by the caller
// (AN-8).
type Credentials struct {
	BearerToken string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient,
// tests inject the in-package double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is an Azure DNS DNS-01 provider bound to a single DNS zone within one
// subscription and resource group.
type Provider struct {
	subscriptionID string
	resourceGroup  string
	zone           string // the DNS zone name, e.g. "example.com" (no trailing dot)
	endpoint       string // base URL, no trailing slash
	host           string // host[:port] of endpoint, for the net.dial grant
	creds          Credentials
	doer           HTTPDoer
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the Azure Resource Manager endpoint (for tests or the
// sovereign-cloud partitions).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns an Azure DNS provider that manages TXT records in zone, within
// subscriptionID/resourceGroup, authorized by creds. The endpoint defaults to the
// public Azure Resource Manager host.
func New(subscriptionID, resourceGroup, zone string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		subscriptionID: subscriptionID,
		resourceGroup:  resourceGroup,
		zone:           strings.TrimSuffix(zone, "."),
		creds:          creds,
		doer:           http.DefaultClient,
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
func (p *Provider) Name() string { return "azuredns" }

// Capabilities declares the least privilege the provider needs: reach the Azure
// management endpoint over the network. No filesystem, no exec, no other host
// (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes (or refreshes) the TXT record name=value with a PUT to the
// record set's resource URL. Azure treats the PUT as an upsert of the whole record
// set, so re-presenting the same record is idempotent (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	body, err := json.Marshal(recordSet{
		Properties: recordSetProperties{
			TTL:        txtTTL,
			TXTRecords: []txtRecord{{Value: []string{value}}},
		},
	})
	if err != nil {
		return fmt.Errorf("azuredns: encode record set: %w", err)
	}
	if err := p.do(ctx, http.MethodPut, name, body, false); err != nil {
		return fmt.Errorf("azuredns: present %s: %w", name, err)
	}
	return nil
}

// CleanupTXT removes the TXT record set for name with a DELETE. A 404 (the record
// set is already gone) is treated as a no-op, so a retried cleanup never errors and
// never leaves the zone in an inconsistent state (AN-5). value is unused: Azure
// deletes the record set as a whole, which for a transient _acme-challenge record is
// the intended cleanup.
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	if err := p.do(ctx, http.MethodDelete, name, nil, true); err != nil {
		return fmt.Errorf("azuredns: cleanup %s: %w", name, err)
	}
	return nil
}

// do builds an authorized request for the TXT record set named by the FQDN name and
// runs it through the shared cloudhttp round-trip (bounded read, non-2xx
// normalisation, drain; CODE-006). allow404 maps a 404 to success (the idempotent-
// cleanup case); any other non-2xx becomes an *apiError whose text never carries the
// bearer token (AN-8). Azure DNS returns no body the provider reads, so out is nil.
func (p *Provider) do(ctx context.Context, method, name string, body []byte, allow404 bool) error {
	endpoint := p.recordSetURL(name)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.creds.BearerToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := cloudhttp.JSON(p.doer, req, nil); err != nil {
		var se *cloudhttp.StatusError
		if errors.As(err, &se) {
			if allow404 && se.StatusCode == http.StatusNotFound {
				return nil
			}
			return &apiError{status: se.StatusCode, body: se.Body}
		}
		return err
	}
	return nil
}

// recordSetURL builds the Azure DNS record-set resource URL for the TXT record whose
// FQDN is name, carrying the api-version query parameter:
//
//	{endpoint}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/
//	dnsZones/{zone}/TXT/{relativeName}?api-version=2018-05-01
func (p *Provider) recordSetURL(name string) string {
	rel := p.relativeName(name)
	path := "/subscriptions/" + p.subscriptionID +
		"/resourceGroups/" + p.resourceGroup +
		"/providers/Microsoft.Network/dnsZones/" + p.zone +
		"/TXT/" + url.PathEscape(rel)
	return p.endpoint + path + "?api-version=" + apiVersion
}

// relativeName converts an FQDN ("_acme-challenge.host.example.com") to the
// record-set name Azure expects, which is relative to the zone: it strips a trailing
// dot and the trailing "."+zone suffix. A name that is exactly the zone (the apex)
// becomes "@", Azure's apex record name.
func (p *Provider) relativeName(name string) string {
	n := strings.TrimSuffix(name, ".")
	if n == p.zone {
		return "@"
	}
	if rel := strings.TrimSuffix(n, "."+p.zone); rel != n {
		return rel
	}
	// name is not under the zone (e.g. a misconfiguration); send it as-is rather
	// than guessing — the API will reject a record outside the zone.
	return n
}

// recordSet is the Azure DNS record-set resource body for a PUT upsert.
type recordSet struct {
	Properties recordSetProperties `json:"properties"`
}

type recordSetProperties struct {
	TTL        int         `json:"TTL"`
	TXTRecords []txtRecord `json:"TXTRecords"`
}

// txtRecord is one TXT record within the set; Value holds the (possibly chunked)
// strings of a single TXT record, here always one DNS-01 authorization value.
type txtRecord struct {
	Value []string `json:"value"`
}

// apiError is a non-2xx Azure DNS response. Its body is the service error text and
// never carries the bearer token (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("azuredns: status %d: %s", e.status, e.body)
}
