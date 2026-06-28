// Package smallstep is the Smallstep (step-ca) CA plugin (F4, sprint S4.11),
// built from the CA-plugin template (internal/ca/catemplate): it implements only
// the CA-specific Backend and the template contributes the rest.
//
// step-ca's distinctive enrollment is its /1.0/sign endpoint, authorized by a
// one-time token (OTT) — a short-lived JWS the client mints with a provisioner
// key. This plugin uses a JWK provisioner with a symmetric (HS256) key: it mints
// the OTT through the jose crypto boundary and POSTs {csr, ott} to /1.0/sign,
// then assembles the returned leaf and chain into a PEM chain. The OTT signing
// stays in the boundary, so the package holds no crypto/* (AN-3); the provisioner
// secret is []byte, never a string (AN-8). It custodies no issuing key — step-ca
// does — so AN-4 is not implicated; on the platform it runs behind
// ca.IssuanceService for idempotency (AN-5) and the outbox (AN-6).
package smallstep

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

const (
	signPath    = "/1.0/sign"
	maxBody     = 1 << 20
	ottValidity = 5 * time.Minute
)

// Config holds the step-ca connection and JWK-provisioner settings.
type Config struct {
	Name            string
	BaseURL         string // step-ca URL, e.g. https://ca.internal:9000
	ProvisionerName string // the JWK provisioner's name (OTT "iss")
	ProvisionerKey  []byte // the JWK provisioner's symmetric (HS256) secret
}

// backend mints OTTs and calls step-ca's /1.0/sign. It is the only CA-specific
// code; the template supplies the ca.CA behaviour.
type backend struct {
	cfg          Config
	client       *http.Client
	now          func() time.Time
	customClient bool
	privateCIDRs []netip.Prefix
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (custom timeout/transport, tests, or a
// process egress-guard client). The supplied client owns endpoint policy.
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
			b.customClient = true
		}
	}
}

// WithPrivateEndpointCIDRs allowlists private step-ca endpoint CIDRs while keeping
// the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// New builds the Smallstep plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	b := &backend{cfg: cfg, client: ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{}), now: time.Now}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue mints a one-time token and submits the CSR to step-ca's /1.0/sign.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("smallstep: at least one DNS name is required")
	}
	ott, err := b.mintOTT(req.DNSNames[0], req.DNSNames)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})),
		"ott": ott,
	}
	var out struct {
		Crt       string   `json:"crt"`
		CA        string   `json:"ca"`
		CertChain []string `json:"certChain"`
	}
	if err := b.post(ctx, b.cfg.BaseURL+signPath, payload, &out); err != nil {
		return nil, err
	}
	return assembleChain(out.Crt, out.CA, out.CertChain)
}

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("smallstep", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
}

// mintOTT builds and signs a step-ca one-time token through the jose boundary.
func (b *backend) mintOTT(subject string, sans []string) (string, error) {
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	now := b.now()
	claims := map[string]any{
		"iss":  b.cfg.ProvisionerName,
		"aud":  b.cfg.BaseURL + signPath,
		"sub":  subject,
		"sans": sans,
		"iat":  now.Unix(),
		"nbf":  now.Add(-time.Minute).Unix(),
		"exp":  now.Add(ottValidity).Unix(),
		"jti":  hex.EncodeToString(nonce),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jose.SignHS256(b.cfg.ProvisionerKey, payload), nil
}

// assembleChain prefers the certChain (leaf first) and falls back to crt+ca.
func assembleChain(crt, ca string, certChain []string) ([]byte, error) {
	parts := certChain
	if len(parts) == 0 {
		if crt != "" {
			parts = append(parts, crt)
		}
		if ca != "" {
			parts = append(parts, ca)
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("smallstep: sign response carried no certificate")
	}
	var out []byte
	for _, p := range parts {
		out = append(out, []byte(p)...)
		if !strings.HasSuffix(p, "\n") {
			out = append(out, '\n')
		}
	}
	return out, nil
}

// post issues a JSON POST, decoding the response into out and mapping a step-ca
// error to a Go error.
func (b *backend) post(ctx context.Context, url string, body, out any) error {
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
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("smallstep: POST %s: %w", url, err)
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
			return fmt.Errorf("smallstep: decode response: %w", err)
		}
	}
	return nil
}

// apiError maps a step-ca error body ({"message": ...}) to a Go error.
func apiError(status int, data []byte) error {
	var env struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &env); err == nil && env.Message != "" {
		return fmt.Errorf("smallstep: api error %d: %s", status, env.Message)
	}
	return fmt.Errorf("smallstep: api error %d", status)
}
