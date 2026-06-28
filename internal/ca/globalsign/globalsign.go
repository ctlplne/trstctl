// Package globalsign is the GlobalSign Atlas/HVCA CA plugin. It implements the
// CA-specific backend behind internal/ca/catemplate: submit a PEM CSR to
// /v2/certificates, then retrieve the issued certificate by serial number.
//
// GlobalSign custodies the signing key and production mTLS is supplied by the
// configured HTTP transport, so this package does not import crypto/* and never
// handles private-key material (AN-3/AN-4). API credentials live as []byte and
// are converted only at the HTTP-header edge (AN-8). Platform issuance runs this
// CA through ca.IssuanceService for idempotency and outbox evidence (AN-5/AN-6).
package globalsign

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultName = "globalsign"
	defaultPoll = 500 * time.Millisecond
	maxPolls    = 60
	maxBody     = 1 << 20
)

// Config holds the GlobalSign API endpoint and header credentials.
type Config struct {
	Name      string
	BaseURL   string // e.g. https://emea.api.hvca.globalsign.com:8443
	APIKey    []byte // AN-8: []byte, never logged
	APISecret []byte // AN-8: []byte, never logged
}

// String renders Config without API credential material.
func (c Config) String() string {
	return fmt.Sprintf("globalsign.Config{Name:%q BaseURL:%q APIKey:%s APISecret:%s}",
		c.Name, c.BaseURL, secretLabel(c.APIKey), secretLabel(c.APISecret))
}

// GoString redacts credentials for %#v renders.
func (c Config) GoString() string { return c.String() }

// LogValue redacts credentials for slog.Any("config", cfg).
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", c.Name),
		slog.String("base_url", c.BaseURL),
		slog.String("api_key", secretLabel(c.APIKey)),
		slog.String("api_secret", secretLabel(c.APISecret)),
	)
}

func secretLabel(secret []byte) string {
	if len(secret) == 0 {
		return "<empty>"
	}
	return "[redacted]"
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
// transport GlobalSign requires; tests can use an httptest-backed client; airgap
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

// WithPrivateEndpointCIDRs allowlists private GlobalSign-compatible endpoint
// CIDRs while keeping the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// WithPollInterval sets the delay between serial retrieval polls.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the GlobalSign plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	cfg = normalizeConfig(cfg)
	cfg.APIKey = secrettext.Clone(cfg.APIKey)
	cfg.APISecret = secrettext.Clone(cfg.APISecret)
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
	return cfg
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue submits an order, then retrieves the issued chain by serial number.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if b.cfg.BaseURL == "" {
		return nil, fmt.Errorf("globalsign: base URL is required")
	}
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
	if len(b.cfg.APIKey) == 0 || len(b.cfg.APISecret) == 0 {
		return nil, fmt.Errorf("globalsign: API key and secret are required")
	}
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("globalsign: at least one DNS name is required")
	}
	out, err := b.submitOrder(ctx, req)
	if err != nil {
		return nil, err
	}
	if out.Status == "issued" && strings.TrimSpace(out.Certificate) != "" {
		return assembleChain(out.Certificate, out.Chain)
	}
	if out.SerialNumber == "" {
		return nil, fmt.Errorf("globalsign: order response carried no serial number")
	}
	return b.awaitCertificate(ctx, out.SerialNumber)
}

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("globalsign", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
}

func (b *backend) submitOrder(ctx context.Context, req ca.IssueRequest) (certificateResponse, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	payload := certificateRequest{
		CSR:       string(csrPEM),
		SubjectDN: subjectDNRequest{CommonName: req.DNSNames[0]},
		SAN:       sanRequest{DNSNames: req.DNSNames},
	}
	var out certificateResponse
	if err := b.doJSON(ctx, http.MethodPost, b.certificatesURL(), payload, &out); err != nil {
		return certificateResponse{}, err
	}
	return out, nil
}

func (b *backend) awaitCertificate(ctx context.Context, serial string) ([]byte, error) {
	for attempt := 0; attempt < maxPolls; attempt++ {
		var out certificateResponse
		if err := b.doJSON(ctx, http.MethodGet, b.certificateURL(serial), nil, &out); err != nil {
			return nil, err
		}
		switch out.Status {
		case "issued":
			if strings.TrimSpace(out.Certificate) == "" {
				return nil, fmt.Errorf("globalsign: certificate %s is issued but missing certificate PEM", serial)
			}
			return assembleChain(out.Certificate, out.Chain)
		case "rejected", "denied", "failed":
			return nil, fmt.Errorf("globalsign: certificate %s was %s", serial, out.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.poll):
		}
	}
	return nil, fmt.Errorf("globalsign: certificate %s was not issued within the polling window", serial)
}

type certificateRequest struct {
	CSR       string           `json:"csr"`
	SubjectDN subjectDNRequest `json:"subject_dn"`
	SAN       sanRequest       `json:"san,omitempty"`
}

type subjectDNRequest struct {
	CommonName string `json:"common_name"`
}

type sanRequest struct {
	DNSNames []string `json:"dns_names,omitempty"`
}

type certificateResponse struct {
	SerialNumber string `json:"serial_number"`
	Status       string `json:"status"`
	Certificate  string `json:"certificate,omitempty"`
	Chain        string `json:"chain,omitempty"`
}

func (b *backend) certificatesURL() string {
	return b.cfg.BaseURL + "/v2/certificates"
}

func (b *backend) certificateURL(serial string) string {
	return b.certificatesURL() + "/" + serial
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
	b.setAuth(req)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("globalsign: %s %s: %w", method, url, err)
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
			return fmt.Errorf("globalsign: decode response: %w", err)
		}
	}
	return nil
}

func (b *backend) setAuth(r *http.Request) {
	r.Header.Set("ApiKey", secrettext.String(b.cfg.APIKey))
	r.Header.Set("ApiSecret", secrettext.String(b.cfg.APISecret))
}

func apiError(status int, data []byte) error {
	msg := errorMessage(data)
	if msg == "" {
		return fmt.Errorf("globalsign: api error %d", status)
	}
	return fmt.Errorf("globalsign: api error %d: %s", status, msg)
}

func errorMessage(data []byte) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return ""
	}
	for _, key := range []string{"error", "message"} {
		if v, ok := raw[key]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err == nil && s != "" {
				return s
			}
		}
	}
	if v, ok := raw["errors"]; ok {
		var list []string
		if err := json.Unmarshal(v, &list); err == nil && len(list) > 0 {
			return strings.Join(list, "; ")
		}
		var objects []struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal(v, &objects); err == nil && len(objects) > 0 {
			if objects[0].Code != "" && objects[0].Message != "" {
				return objects[0].Code + ": " + objects[0].Message
			}
			return objects[0].Message
		}
	}
	return ""
}

func assembleChain(cert, chain string) ([]byte, error) {
	if strings.TrimSpace(cert) == "" {
		return nil, fmt.Errorf("globalsign: response carried no certificate")
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
