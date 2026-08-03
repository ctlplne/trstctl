// SPDX-License-Identifier: MPL-2.0

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
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	neturl "net/url"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	enrollPath = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
	// EJBCA revokes by issuer DN and serial, as a PUT with query parameters
	// (REST API v1 /certificate/{issuer_dn}/{serial}/revoke).
	revokePathFmt = "/ejbca/ejbca-rest-api/v1/certificate/%s/%s/revoke"
	maxBody       = 1 << 20
)

// Config holds the EJBCA connection and enrollment settings.
//
// Token (the OAuth2 bearer) and Password (the end-entity enrollment code) are
// secrets; they are held as []byte, never a string, so they can be wiped and are
// not freely copied by the GC (AN-8). The profile/CA/username fields are
// non-secret identifiers.
type Config struct {
	Name    string
	BaseURL string // e.g. https://ejbca.example.com
	Token   []byte // OAuth2 bearer token (AN-8: []byte); empty means rely on the http.Client's mTLS client cert

	CAName             string // certificate_authority_name
	CertificateProfile string // certificate_profile_name
	EndEntityProfile   string // end_entity_profile_name
	Username           string // end-entity username (defaults to the first SAN)
	Password           []byte // end-entity enrollment code (AN-8: []byte, never logged)
}

// backend talks the EJBCA REST API. It is the only CA-specific code; the template
// supplies the ca.CA behaviour.
type backend struct {
	cfg          Config
	client       *http.Client
	customClient bool
	privateCIDRs []netip.Prefix
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (e.g. one configured with a TLS client
// certificate for EJBCA's mutual-TLS auth, a custom timeout, tests, or a process
// egress-guard client). The supplied client owns endpoint policy.
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
			b.customClient = true
		}
	}
}

// WithPrivateEndpointCIDRs allowlists private EJBCA endpoint CIDRs while keeping
// the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// New builds the EJBCA plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	cfg.Token = secrettext.Clone(cfg.Token)
	cfg.Password = secrettext.Clone(cfg.Password)
	b := &backend{cfg: cfg, client: ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Destroy erases the one-shot bearer/enrollment credentials.
func (b *backend) Destroy() {
	secret.Wipe(b.cfg.Token)
	secret.Wipe(b.cfg.Password)
	if b.client != nil {
		b.client.CloseIdleConnections()
	}
}

// Issue enrolls the CSR via pkcs10enroll and assembles the issued PEM chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
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
		// The enrollment code stays byte-backed until json.Marshal writes the
		// bounded request buffer. That buffer is erased immediately after use.
		"password":        secretjson.StringBytes(b.cfg.Password),
		"include_chain":   true,
		"response_format": "DER",
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

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("ejbca", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
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

// put issues a bodyless JSON PUT, used by revocation (epic R2). It shares the
// post path's auth, bounded read, and status-only error normalization so a
// revocation cannot leak an EJBCA response body that a post would have
// redacted.
func (b *backend) put(ctx context.Context, url string, out any) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return err
	}
	if len(b.cfg.Token) != 0 {
		httpReq.Header.Set("Authorization", secrettext.Prefixed("Bearer ", b.cfg.Token))
	}
	httpReq.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return errors.New("ejbca: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := secret.ReadBounded(resp.Body, maxBody)
	if err != nil {
		return errors.New("ejbca: read response failed")
	}
	defer secret.Wipe(data)
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

// post issues a JSON POST, attaching bearer auth when configured, decoding the
// response into out and normalizing EJBCA failures to status-only errors.
func (b *backend) post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(buf)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	if len(b.cfg.Token) != 0 {
		// net/http forces header values to string. Keep that conversion at the
		// final wire edge and never retain or format the resulting value.
		httpReq.Header.Set("Authorization", secrettext.Prefixed("Bearer ", b.cfg.Token))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return errors.New("ejbca: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := secret.ReadBounded(resp.Body, maxBody)
	if err != nil {
		return errors.New("ejbca: read response failed")
	}
	defer secret.Wipe(data)
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

// apiError deliberately ignores EJBCA's free-form error_message. Upstreams and
// gateways have been observed to echo request credentials into error bodies;
// the bounded HTTP status is the only safe diagnostic allowed to escape.
func apiError(status int, _ []byte) error {
	return fmt.Errorf("ejbca: api error %d", status)
}

var _ catemplate.RevokingBackend = (*backend)(nil)

// Revoke revokes through EJBCA's REST API (epic R2).
//
// EJBCA addresses a certificate by issuer DN and serial, so both are required.
// The reason is mapped to EJBCA's own vocabulary rather than passed through as
// a number: sending an RFC 5280 code EJBCA does not recognize fails the call,
// and an operator revoking a compromised key should not have that turn on a
// vocabulary mismatch.
func (b *backend) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	serial := strings.TrimSpace(req.Serial)
	if serial == "" {
		return fmt.Errorf("ejbca: revocation needs a serial number; none supplied")
	}
	issuerDN := strings.TrimSpace(b.cfg.CAName)
	if issuerDN == "" {
		return fmt.Errorf("ejbca: revocation needs the issuing CA name; none configured")
	}
	if err := b.validateEndpoint(); err != nil {
		return err
	}
	url := b.cfg.BaseURL + fmt.Sprintf(revokePathFmt, neturl.PathEscape(issuerDN), neturl.PathEscape(serial)) +
		"?reason=" + neturl.QueryEscape(ejbcaReason(req.ReasonCode))
	var out struct {
		RevocationStatus string `json:"revocation_status"`
	}
	if err := b.put(ctx, url, &out); err != nil {
		return fmt.Errorf("ejbca: revoke %s: %w", serial, err)
	}
	return nil
}

// ejbcaReason maps an RFC 5280 CRLReason to EJBCA's enumeration. Anything
// unrecognized becomes UNSPECIFIED rather than failing the revocation: getting
// the certificate revoked matters more than recording a precise reason, and the
// reason is preserved in trstctl's own event either way.
func ejbcaReason(code int) string {
	switch code {
	case 1:
		return "KEY_COMPROMISE"
	case 2:
		return "CA_COMPROMISE"
	case 3:
		return "AFFILIATION_CHANGED"
	case 4:
		return "SUPERSEDED"
	case 5:
		return "CESSATION_OF_OPERATION"
	case 6:
		return "CERTIFICATE_HOLD"
	case 9:
		return "PRIVILEGE_WITHDRAWN"
	default:
		return "UNSPECIFIED"
	}
}
