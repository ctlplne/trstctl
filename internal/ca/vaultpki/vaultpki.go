// Package vaultpki is the HashiCorp Vault PKI CA plugin. It implements the
// CA-specific backend behind internal/ca/catemplate: PEM-encode the CSR, POST it
// to Vault's /v1/{mount}/sign/{role} endpoint, and return the leaf+chain PEM.
//
// Vault custodies the signing key, so this package never handles private-key
// material and does not import crypto/* (AN-3/AN-4). The Vault token is held as
// []byte and is only converted to the string form required by net/http at the
// header edge (AN-8). On the platform this CA runs behind ca.IssuanceService,
// which supplies idempotency and the outbox/audit rails for external issuance
// attempts (AN-5/AN-6).
package vaultpki

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
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultMount = "pki"
	defaultName  = "vaultpki"
	defaultTTL   = 365 * 24 * time.Hour
	maxBody      = 1 << 20
)

// Config holds the Vault PKI connection and issuance settings.
type Config struct {
	Name       string
	BaseURL    string        // Vault address, e.g. https://vault.example.com:8200
	Token      []byte        // Vault token (AN-8: []byte, never logged)
	Mount      string        // PKI mount path; default "pki"
	Role       string        // Vault PKI role used for signing
	DefaultTTL time.Duration // used when ca.IssueRequest.TTL is empty
}

// String renders Config without secret material so accidental fmt/slog bridges do
// not expose the Vault token.
func (c Config) String() string {
	return fmt.Sprintf("vaultpki.Config{Name:%q BaseURL:%q Token:%s Mount:%q Role:%q DefaultTTL:%s}",
		c.Name, c.BaseURL, tokenLabel(c.Token), c.Mount, c.Role, c.DefaultTTL)
}

// GoString redacts Token for %#v renders.
func (c Config) GoString() string { return c.String() }

// LogValue redacts Token for slog.Any("config", cfg).
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", c.Name),
		slog.String("base_url", c.BaseURL),
		slog.String("token", tokenLabel(c.Token)),
		slog.String("mount", c.Mount),
		slog.String("role", c.Role),
		slog.Duration("default_ttl", c.DefaultTTL),
	)
}

func tokenLabel(token []byte) string {
	if len(token) == 0 {
		return "<empty>"
	}
	return "[redacted]"
}

type backend struct {
	cfg          Config
	client       *http.Client
	customClient bool
	privateCIDRs []netip.Prefix
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (custom timeout/transport/mTLS, tests, or a
// process egress-guard client). The supplied client owns endpoint policy.
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
			b.customClient = true
		}
	}
}

// WithPrivateEndpointCIDRs allowlists private Vault endpoint CIDRs while keeping
// the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// New builds the Vault PKI plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	cfg = normalizeConfig(cfg)
	cfg.Token = secrettext.Clone(cfg.Token)
	b := &backend{cfg: cfg, client: ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})}
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
	cfg.Mount = strings.Trim(strings.TrimSpace(cfg.Mount), "/")
	if cfg.Mount == "" {
		cfg.Mount = defaultMount
	}
	cfg.Role = strings.Trim(strings.TrimSpace(cfg.Role), "/")
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultTTL
	}
	return cfg
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue submits the CSR to Vault PKI and returns the PEM chain Vault issued.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if b.cfg.BaseURL == "" {
		return nil, fmt.Errorf("vaultpki: base URL is required")
	}
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
	if len(b.cfg.Token) == 0 {
		return nil, fmt.Errorf("vaultpki: token is required")
	}
	if b.cfg.Role == "" {
		return nil, fmt.Errorf("vaultpki: role is required")
	}
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("vaultpki: at least one DNS name is required")
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	payload := map[string]any{
		"csr":         string(csrPEM),
		"common_name": req.DNSNames[0],
		"alt_names":   strings.Join(req.DNSNames, ","),
		"ttl":         vaultTTL(req.TTL, b.cfg.DefaultTTL),
	}
	var env vaultEnvelope
	if err := b.postJSON(ctx, b.signURL(), payload, &env); err != nil {
		return nil, err
	}
	if len(env.Errors) > 0 {
		return nil, fmt.Errorf("vaultpki: api error: %s", strings.Join(env.Errors, "; "))
	}
	return assembleChain(env.Data)
}

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("vaultpki", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
}

func vaultTTL(requested, fallback time.Duration) string {
	d := requested
	if d <= 0 {
		d = fallback
	}
	if d <= 0 {
		d = defaultTTL
	}
	secs := int64(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10) + "s"
}

func (b *backend) signURL() string {
	return b.cfg.BaseURL + "/v1/" + b.cfg.Mount + "/sign/" + b.cfg.Role
}

type vaultEnvelope struct {
	Data     signData `json:"data"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type signData struct {
	Certificate  string   `json:"certificate"`
	IssuingCA    string   `json:"issuing_ca"`
	CAChain      []string `json:"ca_chain"`
	SerialNumber string   `json:"serial_number"`
	Expiration   int64    `json:"expiration"`
}

func (b *backend) postJSON(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Vault-Token", secrettext.String(b.cfg.Token))
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("vaultpki: POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vaultAPIError(resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("vaultpki: decode response: %w", err)
		}
	}
	return nil
}

func vaultAPIError(status int, data []byte) error {
	var env struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(data, &env); err == nil && len(env.Errors) > 0 {
		return fmt.Errorf("vaultpki: api error %d: %s", status, strings.Join(env.Errors, "; "))
	}
	return fmt.Errorf("vaultpki: api error %d", status)
}

func assembleChain(data signData) ([]byte, error) {
	if strings.TrimSpace(data.Certificate) == "" {
		return nil, fmt.Errorf("vaultpki: sign response carried no certificate")
	}
	parts := []string{data.Certificate}
	if len(data.CAChain) > 0 {
		parts = append(parts, data.CAChain...)
	} else if strings.TrimSpace(data.IssuingCA) != "" {
		parts = append(parts, data.IssuingCA)
	}
	var out []byte
	for _, part := range parts {
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
