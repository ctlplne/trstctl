// Package route53 is the AWS Route 53 reference DNS-01 provider (S8b.1), the first
// provider built from the DNS-provider plugin template — the acme.DNSProvider
// interface plus the acme.ConformDNSProvider harness. It publishes and retracts the
// _acme-challenge TXT records the DNS-01 solver needs by calling Route 53's
// ChangeResourceRecordSets API (UPSERT to present, DELETE to clean up) over HTTPS,
// signed with AWS Signature Version 4.
//
// Like the ACM deployment connector (internal/connector/acm), the keyed MAC and
// digests route through the crypto boundary (internal/crypto; AN-3) and the package
// imports no crypto/*. API credentials are carried as opaque strings, are never
// logged, and are sealed at rest by the caller via the platform secret store
// (AN-8). A provider does exactly two things — present and clean up a TXT record in
// one hosted zone — and makes no other outbound calls; its capability grant is
// net.dial to the Route 53 host only (the least-privilege pattern of the connector
// SDK, S5.5).
//
// Idempotency (AN-5): PresentTXT is an UPSERT, so re-presenting the same record is a
// no-op; CleanupTXT treats "record not found" as success, so a retried cleanup never
// errors and never orphans records. When the solver runs inside the issuance path,
// that path provides the outbox delivery (AN-6).
package route53

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/pluginhost"
	"trustctl.io/trustctl/internal/protocols/acme"
)

const (
	service     = "route53"
	sigV4Region = "us-east-1" // Route 53 is a global service; SigV4 always uses us-east-1.
	apiVersion  = "2013-04-01"
	xmlns       = "https://route53.amazonaws.com/doc/2013-04-01/"
	txtTTL      = 60
)

// Provider satisfies the DNS-01 plugin template.
var _ acme.DNSProvider = (*Provider)(nil)

// Credentials are the AWS access credentials used to sign Route 53 requests.
// SessionToken is set for temporary (STS/role) credentials. They are opaque to this
// package, never logged, and sealed at rest by the caller (AN-8).
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient,
// tests inject the r53test double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider is a Route 53 DNS-01 provider bound to a single hosted zone.
type Provider struct {
	zoneID   string
	endpoint string // base URL, no trailing slash
	host     string // host[:port] of endpoint, for the net.dial grant and signing
	creds    Credentials
	doer     HTTPDoer
	now      func() time.Time
}

// Option configures a Provider.
type Option func(*Provider)

// WithEndpoint overrides the Route 53 endpoint (for tests, VPC endpoints, or the
// GovCloud/China partitions).
func WithEndpoint(endpoint string) Option {
	return func(p *Provider) { p.setEndpoint(endpoint) }
}

// WithHTTPClient injects the HTTP doer (tests pass the r53test double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(p *Provider) { p.doer = d }
}

// New returns a Route 53 provider that manages TXT records in hostedZoneID, signing
// with creds. The endpoint defaults to the global Route 53 service host.
func New(hostedZoneID string, creds Credentials, opts ...Option) *Provider {
	p := &Provider{
		zoneID: normalizeZoneID(hostedZoneID),
		creds:  creds,
		doer:   http.DefaultClient,
		now:    time.Now,
	}
	p.setEndpoint("https://route53.amazonaws.com")
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

// normalizeZoneID strips a leading "/hostedzone/" so callers may pass either the
// bare ID ("Z123") or the path form Route 53 returns ("/hostedzone/Z123").
func normalizeZoneID(id string) string {
	id = strings.TrimPrefix(id, "/hostedzone/")
	id = strings.TrimPrefix(id, "hostedzone/")
	return id
}

// Name identifies the provider.
func (p *Provider) Name() string { return "aws-route53" }

// Capabilities declares the least privilege the provider needs: reach the Route 53
// endpoint over the network. No filesystem, no exec, no other host (S5.5 lineage).
func (p *Provider) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, p.host)
}

// PresentTXT publishes (or refreshes) the TXT record name=value via an UPSERT, which
// is idempotent: presenting the same record twice is a no-op (AN-5).
func (p *Provider) PresentTXT(ctx context.Context, name, value string) error {
	return p.change(ctx, "UPSERT", name, value)
}

// CleanupTXT removes the TXT record name=value via a DELETE. Removing an absent
// record is treated as a no-op, so a retried cleanup never errors and never leaves
// the zone in an inconsistent state (AN-5).
func (p *Provider) CleanupTXT(ctx context.Context, name, value string) error {
	if err := p.change(ctx, "DELETE", name, value); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (p *Provider) change(ctx context.Context, action, name, value string) error {
	body, err := xml.Marshal(changeRequest{
		Xmlns: xmlns,
		ChangeBatch: changeBatch{Changes: []change{{
			Action: action,
			ResourceRecordSet: resourceRecordSet{
				Name:            name,
				Type:            "TXT",
				TTL:             txtTTL,
				ResourceRecords: []resourceRecord{{Value: quote(value)}},
			},
		}}},
	})
	if err != nil {
		return fmt.Errorf("route53: encode change: %w", err)
	}
	body = append([]byte(xml.Header), body...)

	path := "/" + apiVersion + "/hostedzone/" + p.zoneID + "/rrset"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml")
	p.signV4(req, body, p.now().UTC())

	resp, err := p.doer.Do(req)
	if err != nil {
		return fmt.Errorf("route53: %s %s: %w", action, name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// signV4 adds AWS Signature Version 4 headers to req over body. Digests and the
// keyed MAC route through the crypto boundary (AN-3); identical algorithm to the ACM
// connector, with service="route53" and the global us-east-1 signing region.
func (p *Provider) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if p.creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", p.creds.SessionToken)
	}

	signed := []string{"content-type", "host", "x-amz-date"}
	if p.creds.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = p.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"", // no query
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")

	credScope := dateStamp + "/" + sigV4Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := crypto.HMACSHA256([]byte("AWS4"+p.creds.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(sigV4Region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+p.creds.AccessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}

// quote wraps a TXT value in the double quotes Route 53 stores it under.
func quote(v string) string { return "\"" + v + "\"" }

// changeRequest is the Route 53 ChangeResourceRecordSets request body.
type changeRequest struct {
	XMLName     xml.Name    `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns       string      `xml:"xmlns,attr"`
	ChangeBatch changeBatch `xml:"ChangeBatch"`
}

type changeBatch struct {
	Changes []change `xml:"Changes>Change"`
}

type change struct {
	Action            string            `xml:"Action"`
	ResourceRecordSet resourceRecordSet `xml:"ResourceRecordSet"`
}

type resourceRecordSet struct {
	Name            string           `xml:"Name"`
	Type            string           `xml:"Type"`
	TTL             int              `xml:"TTL"`
	ResourceRecords []resourceRecord `xml:"ResourceRecords>ResourceRecord"`
}

type resourceRecord struct {
	Value string `xml:"Value"`
}

// apiError is a non-2xx Route 53 response. Its body is the service error text and
// never carries request credentials (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("route53: status %d: %s", e.status, e.body) }

// isNotFound reports whether err is Route 53's InvalidChangeBatch "not found",
// returned when DELETEing a record that is already gone — a no-op for cleanup.
func isNotFound(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		b := strings.ToLower(ae.body)
		return strings.Contains(b, "not found") || strings.Contains(b, "notfound")
	}
	return false
}
