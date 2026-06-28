// Package venafi is the Venafi TPP / TLS Protect CA plugin (F4, CLM-04), built
// from the CA-plugin template (internal/ca/catemplate): it implements only the
// CA-specific Backend and the template contributes the ca.CA behavior.
//
// The plugin speaks the TPP Web SDK certificate flow: POST a PKCS#10 CSR to
// /vedsdk/Certificates/Request under a policy DN, then retrieve the issued PEM
// chain from /vedsdk/Certificates/Retrieve. TLS Protect Cloud deployments can be
// fronted by the same adapter shape when they expose a TPP-compatible policy/API
// facade. CSRs are PEM-encoded for the API with encoding/pem; the package holds
// no crypto/* imports (AN-3). The access token is []byte, never string at rest
// (AN-8), and the upstream CA custodies signing keys; on the platform this runs
// behind ca.IssuanceService for idempotency (AN-5) and outbox evidence (AN-6).
package venafi

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
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	requestPath  = "/vedsdk/Certificates/Request"
	retrievePath = "/vedsdk/Certificates/Retrieve"
	maxBody      = 1 << 20
	defaultPoll  = 2 * time.Second
	maxPolls     = 60
)

// Config holds the Venafi connection and enrollment settings.
//
// AccessToken is a TPP/TLS Protect bearer token; it is held as []byte, never a
// string, so it can be wiped and is not freely copied by the GC (AN-8). PolicyDN
// and Application are non-secret routing labels.
type Config struct {
	Name        string
	BaseURL     string // e.g. https://tpp.example.com
	AccessToken []byte // bearer token (AN-8: []byte, never logged)
	PolicyDN    string // e.g. \VED\Policy\Certificates\trstctl
	Application string // optional requester/application label for audit in Venafi
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

// WithHTTPClient sets the HTTP client (custom timeouts, mTLS, tests, or a process
// egress-guard client). The supplied client owns endpoint policy.
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
			b.customClient = true
		}
	}
}

// WithPrivateEndpointCIDRs allowlists private Venafi endpoint CIDRs while keeping
// the default SSRF guard for all other resolved addresses.
func WithPrivateEndpointCIDRs(cidrs ...netip.Prefix) Option {
	return func(b *backend) {
		b.privateCIDRs = append([]netip.Prefix(nil), cidrs...)
		if !b.customClient {
			b.client = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
		}
	}
}

// WithPollInterval sets the delay between retrieve polls while Venafi is issuing.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the Venafi plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	cfg.AccessToken = secrettext.Clone(cfg.AccessToken)
	b := &backend{cfg: cfg, client: ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{}), poll: defaultPoll}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue requests and retrieves a certificate through Venafi TPP/TLS Protect.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if err := b.validateEndpoint(); err != nil {
		return nil, err
	}
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("venafi: at least one DNS name is required")
	}
	certDN, guid, err := b.request(ctx, req)
	if err != nil {
		return nil, err
	}
	return b.retrieve(ctx, certDN, guid)
}

func (b *backend) validateEndpoint() error {
	if b.customClient {
		return nil
	}
	return ca.ValidateExternalCAEndpoint("venafi", b.cfg.BaseURL, ca.HTTPClientConfig{AllowPrivateCIDRs: b.privateCIDRs})
}

func (b *backend) request(ctx context.Context, req ca.IssueRequest) (certificateDN, guid string, err error) {
	commonName := req.DNSNames[0]
	sans := make([]map[string]string, 0, len(req.DNSNames))
	for _, name := range req.DNSNames {
		sans = append(sans, map[string]string{"Type": "DNS", "Name": name})
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	payload := map[string]any{
		"PolicyDN":    b.cfg.PolicyDN,
		"PKCS10":      string(csrPEM),
		"ObjectName":  commonName,
		"Subject":     "CN=" + commonName,
		"SubjectAlt":  sans,
		"Application": b.cfg.Application,
	}
	var out struct {
		CertificateDN string `json:"CertificateDN"`
		GUID          string `json:"Guid"`
	}
	if err := b.post(ctx, b.cfg.BaseURL+requestPath, payload, &out); err != nil {
		return "", "", err
	}
	if out.CertificateDN == "" && out.GUID == "" {
		return "", "", fmt.Errorf("venafi: request returned no CertificateDN or Guid")
	}
	return out.CertificateDN, out.GUID, nil
}

func (b *backend) retrieve(ctx context.Context, certificateDN, guid string) ([]byte, error) {
	payload := map[string]any{
		"CertificateDN": certificateDN,
		"Guid":          guid,
		"Format":        "PEM",
		"IncludeChain":  true,
	}
	var lastStatus string
	for attempt := 0; attempt < maxPolls; attempt++ {
		var out struct {
			CertificateData string `json:"CertificateData"`
			Certificate     string `json:"Certificate"`
			Status          string `json:"Status"`
		}
		if err := b.post(ctx, b.cfg.BaseURL+retrievePath, payload, &out); err != nil {
			return nil, err
		}
		chain := strings.TrimSpace(out.CertificateData)
		if chain == "" {
			chain = strings.TrimSpace(out.Certificate)
		}
		if chain != "" {
			if !strings.HasSuffix(chain, "\n") {
				chain += "\n"
			}
			return []byte(chain), nil
		}
		lastStatus = out.Status
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.poll):
		}
	}
	if lastStatus == "" {
		lastStatus = "pending"
	}
	return nil, fmt.Errorf("venafi: certificate was not issued within the polling window (last status %q)", lastStatus)
}

func (b *backend) post(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	if len(b.cfg.AccessToken) != 0 {
		// string(...) is the transient edge form of the []byte token sent on the
		// wire (AN-8); the long-lived secret stays []byte in Config.
		httpReq.Header.Set("Authorization", "Bearer "+string(b.cfg.AccessToken))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("venafi: POST %s: %w", url, err)
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
			return fmt.Errorf("venafi: decode response: %w", err)
		}
	}
	return nil
}

func apiError(status int, data []byte) error {
	var env struct {
		Error   string `json:"Error"`
		Message string `json:"Message"`
		Code    int    `json:"Code"`
	}
	if err := json.Unmarshal(data, &env); err == nil {
		switch {
		case env.Message != "":
			return fmt.Errorf("venafi: api error %d: %s", status, env.Message)
		case env.Error != "":
			return fmt.Errorf("venafi: api error %d: %s", status, env.Error)
		case env.Code != 0:
			return fmt.Errorf("venafi: api error %d: code %d", status, env.Code)
		}
	}
	return fmt.Errorf("venafi: api error %d", status)
}
