// Package ejbca is the EJBCA CA plugin (F4, sprint S4.10), built from the
// CA-plugin template (internal/ca/catemplate): it implements only the
// CA-specific Backend and the template contributes the rest. It speaks the EJBCA
// REST API — POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll with the CSR
// and the CA / certificate-profile / end-entity-profile names — and assembles
// the base64-DER leaf and chain the API returns into a PEM chain.
//
// EJBCA REST authenticates with either a TLS client certificate (mutual TLS) or
// an OAuth2 bearer token: set Config.Token for bearer auth, or leave it empty and
// supply a TLS-configured client via WithHTTPClient for mTLS. CSRs are
// PEM-encoded with encoding/pem; the package holds no crypto/* (AN-3). It
// custodies no signing key — EJBCA does — so AN-4 is not implicated; on the
// platform it runs behind ca.IssuanceService for idempotency (AN-5) and the
// outbox (AN-6).
package ejbca

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/catemplate"
)

const (
	enrollPath = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
	maxBody    = 1 << 20
)

// Config holds the EJBCA connection and enrollment settings.
type Config struct {
	Name    string
	BaseURL string // e.g. https://ejbca.example.com
	Token   string // OAuth2 bearer token; empty means rely on the http.Client's mTLS client cert

	CAName             string // certificate_authority_name
	CertificateProfile string // certificate_profile_name
	EndEntityProfile   string // end_entity_profile_name
	Username           string // end-entity username (defaults to the first SAN)
	Password           string // end-entity enrollment code
}

// backend talks the EJBCA REST API. It is the only CA-specific code; the template
// supplies the ca.CA behaviour.
type backend struct {
	cfg    Config
	client *http.Client
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (e.g. one configured with a TLS client
// certificate for EJBCA's mutual-TLS auth, or a custom timeout).
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
		}
	}
}

// New builds the EJBCA plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	b := &backend{cfg: cfg, client: http.DefaultClient}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue enrolls the CSR via pkcs10enroll and assembles the issued PEM chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("ejbca: at least one DNS name is required")
	}
	username := b.cfg.Username
	if username == "" {
		username = req.DNSNames[0]
	}
	payload := map[string]any{
		"certificate_request":        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})),
		"certificate_profile_name":   b.cfg.CertificateProfile,
		"end_entity_profile_name":    b.cfg.EndEntityProfile,
		"certificate_authority_name": b.cfg.CAName,
		"username":                   username,
		"password":                   b.cfg.Password,
		"include_chain":              true,
		"response_format":            "DER",
	}
	var out struct {
		Certificate      string   `json:"certificate"`
		SerialNumber     string   `json:"serial_number"`
		ResponseFormat   string   `json:"response_format"`
		CertificateChain []string `json:"certificate_chain"`
	}
	if err := b.post(ctx, b.cfg.BaseURL+enrollPath, payload, &out); err != nil {
		return nil, err
	}
	if out.Certificate == "" {
		return nil, fmt.Errorf("ejbca: enroll returned no certificate")
	}
	return assembleChain(append([]string{out.Certificate}, out.CertificateChain...))
}

// assembleChain turns EJBCA's base64-DER (or PEM) certificate values into a
// concatenated PEM chain, leaf first.
func assembleChain(certs []string) ([]byte, error) {
	var out []byte
	for _, c := range certs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.HasPrefix(c, "-----BEGIN") {
			out = append(out, []byte(c)...)
			if !strings.HasSuffix(c, "\n") {
				out = append(out, '\n')
			}
			continue
		}
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("ejbca: decode certificate: %w", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, nil
}

// post issues a JSON POST, attaching bearer auth when configured, decoding the
// response into out and mapping an EJBCA error envelope to a Go error.
func (b *backend) post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	if b.cfg.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ejbca: POST %s: %w", url, err)
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
			return fmt.Errorf("ejbca: decode response: %w", err)
		}
	}
	return nil
}

// apiError maps an EJBCA {error_code, error_message} envelope to an error.
func apiError(status int, data []byte) error {
	var env struct {
		ErrorCode    int    `json:"error_code"`
		ErrorMessage string `json:"error_message"`
	}
	if err := json.Unmarshal(data, &env); err == nil && env.ErrorMessage != "" {
		return fmt.Errorf("ejbca: api error %d: %s", status, env.ErrorMessage)
	}
	return fmt.Errorf("ejbca: api error %d", status)
}
