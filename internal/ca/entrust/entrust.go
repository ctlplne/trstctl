// Package entrust is the Entrust ECS / CA Gateway CA plugin. It implements the
// CA-specific backend behind internal/ca/catemplate: submit a PEM CSR enrollment
// under a configured CA ID, then poll the tracking ID until Entrust returns the
// issued certificate chain.
//
// Entrust custodies the signing key and production mTLS is supplied by the HTTP
// transport configured by the caller, so this package imports no crypto/* and
// handles no private-key material (AN-3/AN-4). Platform issuance runs it behind
// ca.IssuanceService for idempotency and outbox evidence (AN-5/AN-6).
package entrust

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
)

const (
	defaultName = "entrust"
	defaultPoll = 500 * time.Millisecond
	maxPolls    = 60
	maxBody     = 1 << 20
)

// Config holds the Entrust Gateway endpoint and enrollment routing settings.
type Config struct {
	Name      string
	BaseURL   string // Entrust CA Gateway API base URL
	CAID      string // certificate authority ID in the URL path
	ProfileID string // optional enrollment profile
}

type backend struct {
	cfg          Config
	client       *http.Client
	poll         time.Duration
	customClient bool
	privateCIDRs []netip.Prefix
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client. Production callers can attach the mTLS
// transport Entrust requires; tests can use an httptest-backed client; airgap
// callers can pass a process egress-guard client. The supplied client owns
// endpoint policy.
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
			b.customClient = true
		}
	}
}

// WithPrivateEndpointCIDRs allowlists private Entrust endpoint CIDRs while keeping
// the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// WithPollInterval sets the delay between enrollment status polls.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the Entrust plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	cfg = normalizeConfig(cfg)
	b := &backend{cfg: cfg, client: ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{}), poll: defaultPoll}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

func normalizeConfig(cfg Config) Config {
	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name == "" {
		cfg.Name = defaultName
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	cfg.CAID = strings.Trim(strings.TrimSpace(cfg.CAID), "/")
	cfg.ProfileID = strings.TrimSpace(cfg.ProfileID)
	return cfg
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue submits an enrollment, then retrieves the issued chain by tracking ID.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if b.cfg.BaseURL == "" {
		return nil, fmt.Errorf("entrust: base URL is required")
	}
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
	if b.cfg.CAID == "" {
		return nil, fmt.Errorf("entrust: CA ID is required")
	}
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("entrust: at least one DNS name is required")
	}
	out, err := b.submitEnrollment(ctx, req)
	if err != nil {
		return nil, err
	}
	if statusIssued(out.Status) && strings.TrimSpace(out.Certificate) != "" {
		return assembleChain(out.Certificate, out.Chain)
	}
	if out.TrackingID == "" {
		return nil, fmt.Errorf("entrust: enrollment response carried no tracking ID")
	}
	return b.awaitCertificate(ctx, out.TrackingID)
}

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("entrust", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
}

func (b *backend) submitEnrollment(ctx context.Context, req ca.IssueRequest) (enrollmentResponse, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	sans := make([]san, 0, len(req.DNSNames))
	for _, name := range req.DNSNames {
		sans = append(sans, san{Type: "dNSName", Value: name})
	}
	payload := enrollmentRequest{CSR: string(csrPEM), ProfileID: b.cfg.ProfileID, SubjectAltNames: sans}
	var out enrollmentResponse
	if err := b.doJSON(ctx, http.MethodPost, b.enrollmentsURL(), payload, &out); err != nil {
		return enrollmentResponse{}, err
	}
	return out, nil
}

func (b *backend) awaitCertificate(ctx context.Context, trackingID string) ([]byte, error) {
	for attempt := 0; attempt < maxPolls; attempt++ {
		var out enrollmentResponse
		if err := b.doJSON(ctx, http.MethodGet, b.enrollmentURL(trackingID), nil, &out); err != nil {
			return nil, err
		}
		switch strings.ToUpper(out.Status) {
		case "ISSUED":
			if strings.TrimSpace(out.Certificate) == "" {
				return nil, fmt.Errorf("entrust: enrollment %s is issued but missing certificate PEM", trackingID)
			}
			return assembleChain(out.Certificate, out.Chain)
		case "REJECTED", "DENIED", "FAILED":
			return nil, fmt.Errorf("entrust: enrollment %s was %s", trackingID, out.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.poll):
		}
	}
	return nil, fmt.Errorf("entrust: enrollment %s was not issued within the polling window", trackingID)
}

type enrollmentRequest struct {
	CSR             string `json:"csr"`
	ProfileID       string `json:"profileId,omitempty"`
	SubjectAltNames []san  `json:"subjectAltNames,omitempty"`
}

type san struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type enrollmentResponse struct {
	TrackingID  string `json:"trackingId"`
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	Chain       string `json:"chain,omitempty"`
}

func (b *backend) enrollmentsURL() string {
	return b.cfg.BaseURL + "/v1/certificate-authorities/" + b.cfg.CAID + "/enrollments"
}

func (b *backend) enrollmentURL(trackingID string) string {
	return b.enrollmentsURL() + "/" + trackingID
}

func (b *backend) doJSON(ctx context.Context, method, url string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("entrust: %s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("entrust: decode response: %w", err)
		}
	}
	return nil
}

func apiError(status int, data []byte) error {
	var env struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(data, &env); err == nil {
		switch {
		case env.Code != "" && env.Message != "":
			return fmt.Errorf("entrust: api error %d: %s: %s", status, env.Code, env.Message)
		case env.Message != "":
			return fmt.Errorf("entrust: api error %d: %s", status, env.Message)
		case env.Error != "":
			return fmt.Errorf("entrust: api error %d: %s", status, env.Error)
		}
	}
	return fmt.Errorf("entrust: api error %d", status)
}

func statusIssued(status string) bool {
	return strings.EqualFold(status, "ISSUED")
}

func assembleChain(cert, chain string) ([]byte, error) {
	if strings.TrimSpace(cert) == "" {
		return nil, fmt.Errorf("entrust: response carried no certificate")
	}
	var out []byte
	for _, part := range []string{cert, chain} {
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, []byte(part)...)
		if !strings.HasSuffix(part, "\n") {
			out = append(out, '\n')
		}
	}
	return out, nil
}
