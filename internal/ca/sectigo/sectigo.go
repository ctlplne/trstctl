// Package sectigo is the Sectigo Certificate Manager (SCM) CA plugin (F4, sprint
// S4.8), built from the CA-plugin template (internal/ca/catemplate): it
// implements only the CA-specific Backend and the template contributes the rest.
// It speaks the SCM SSL REST API — enroll with the CSR, then poll collect until
// the order is issued — authenticating with the login/password/customerUri
// headers. SCM issues asynchronously, so collect reports code -183 ("being
// processed") until the chain is ready.
//
// CSRs are PEM-encoded for the API with encoding/pem; the package holds no
// crypto/* (AN-3). It carries no signing key — Sectigo custodies issuance — so
// AN-4 is not implicated; on the platform it runs behind ca.IssuanceService for
// idempotency (AN-5) and the outbox (AN-6).
package sectigo

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/catemplate"
)

const (
	apiBase            = "/api/ssl/v1"
	defaultTermDays    = 365
	defaultPoll        = 2 * time.Second
	maxPolls           = 60
	maxBody            = 1 << 20
	codeBeingProcessed = -183 // SCM "order still being processed"
)

// Config holds the SCM connection and enrollment settings.
type Config struct {
	Name        string
	BaseURL     string // e.g. https://cert-manager.com
	Login       string
	Password    string
	CustomerURI string
	OrgID       int // organization/department the certificate is issued under
	CertType    int // SCM certificate profile/type id
}

// backend talks the SCM SSL REST API. It is the only CA-specific code; the
// template supplies the ca.CA behaviour.
type backend struct {
	cfg    Config
	client *http.Client
	poll   time.Duration
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (custom timeouts/transport).
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
		}
	}
}

// WithPollInterval sets the delay between collect polls while SCM is issuing.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the Sectigo plugin. The returned *catemplate.Plugin is a ca.CA.
func New(cfg Config, opts ...Option) *catemplate.Plugin {
	b := &backend{cfg: cfg, client: http.DefaultClient, poll: defaultPoll}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Issue enrolls the CSR with SCM and collects the issued chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("sectigo: at least one DNS name is required")
	}
	sslID, err := b.enroll(ctx, req)
	if err != nil {
		return nil, err
	}
	return b.collect(ctx, sslID)
}

// enroll submits the CSR and returns the SCM certificate id (sslId).
func (b *backend) enroll(ctx context.Context, req ca.IssueRequest) (int, error) {
	term := int(req.TTL / (24 * time.Hour))
	if term < 1 {
		term = defaultTermDays
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	payload := map[string]any{
		"orgId":         b.cfg.OrgID,
		"csr":           string(csrPEM),
		"certType":      b.cfg.CertType,
		"term":          term,
		"numberServers": 1,
		"serverType":    -1,
		"subjAltNames":  strings.Join(req.DNSNames, ","),
		"comments":      "Issued by certctl",
	}
	var out struct {
		SSLID   int    `json:"sslId"`
		RenewID string `json:"renewId"`
	}
	if err := b.postJSON(ctx, b.cfg.BaseURL+apiBase+"/enroll", payload, &out); err != nil {
		return 0, err
	}
	if out.SSLID == 0 {
		return 0, fmt.Errorf("sectigo: enroll returned no sslId")
	}
	return out.SSLID, nil
}

// collect polls for the issued chain, returning it once SCM stops reporting
// "being processed". The bounded poll covers a double's immediate issuance and a
// brief real delay; the outbox (AN-6) absorbs longer waits on the platform.
func (b *backend) collect(ctx context.Context, sslID int) ([]byte, error) {
	url := b.cfg.BaseURL + apiBase + "/collect/" + strconv.Itoa(sslID) + "/pem"
	for attempt := 0; attempt < maxPolls; attempt++ {
		chain, pending, err := b.tryCollect(ctx, url)
		if err != nil {
			return nil, err
		}
		if !pending {
			return chain, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.poll):
		}
	}
	return nil, fmt.Errorf("sectigo: certificate %d was not issued within the polling window", sslID)
}

// tryCollect performs one collect: the PEM chain on 200, pending=true when SCM
// reports code -183, or a fatal error otherwise.
func (b *backend) tryCollect(ctx context.Context, url string) (chain []byte, pending bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	b.setAuth(httpReq)
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, false, fmt.Errorf("sectigo: collect: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == http.StatusOK {
		return data, false, nil
	}
	code, desc := parseError(data)
	if code == codeBeingProcessed {
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("sectigo: collect: api error %d: code %d: %s", resp.StatusCode, code, desc)
}

// postJSON issues a JSON POST, decoding the response into out and mapping an SCM
// error envelope to a Go error.
func (b *backend) postJSON(ctx context.Context, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	b.setAuth(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sectigo: POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		code, desc := parseError(data)
		return fmt.Errorf("sectigo: api error %d: code %d: %s", resp.StatusCode, code, desc)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("sectigo: decode response: %w", err)
		}
	}
	return nil
}

func (b *backend) setAuth(r *http.Request) {
	r.Header.Set("login", b.cfg.Login)
	r.Header.Set("password", b.cfg.Password)
	r.Header.Set("customerUri", b.cfg.CustomerURI)
	r.Header.Set("Accept", "application/json")
}

// parseError reads an SCM {code, description} envelope.
func parseError(data []byte) (code int, description string) {
	var env struct {
		Code        int    `json:"code"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(data, &env)
	return env.Code, env.Description
}
