package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/protocol"
)

const maxEnrollBody = 1 << 20

// HTTPEnroller is an Enroller that talks to a control-plane enrollment endpoint
// (enroll.Handler) over HTTP. It submits CSRs (never keys) and returns the issued
// certificate chain.
type HTTPEnroller struct {
	base   *url.URL
	client *http.Client
	err    error
}

var _ Enroller = (*HTTPEnroller)(nil)

type httpEnrollerOptions struct {
	allowLoopbackDevHTTP bool
}

// HTTPEnrollerOption configures an HTTPEnroller.
type HTTPEnrollerOption func(*httpEnrollerOptions)

// WithLoopbackDevHTTP allows cleartext HTTP only for explicit loopback development
// endpoints. Production bootstrap tokens must use HTTPS with an explicit CA-pinned
// client because the token is a one-time credential.
func WithLoopbackDevHTTP() HTTPEnrollerOption {
	return func(o *httpEnrollerOptions) {
		o.allowLoopbackDevHTTP = true
	}
}

// NewHTTPEnroller returns an enroller posting to baseURL. Non-loopback bootstrap
// traffic is fail-closed unless baseURL is HTTPS and the caller supplies an explicit
// HTTP client, normally one constructed from the operator CA bundle. That prevents a
// one-time bootstrap token from riding plaintext or ambient system roots.
func NewHTTPEnroller(baseURL string, client *http.Client, opts ...HTTPEnrollerOption) *HTTPEnroller {
	cfg := httpEnrollerOptions{}
	for _, opt := range opts {
		opt(&cfg)
	}
	base, err := validateEnrollmentBaseURL(baseURL, client, cfg.allowLoopbackDevHTTP)
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPEnroller{base: base, client: client, err: err}
}

// EnrollBootstrap posts the token and CSR to the bootstrap endpoint.
func (h *HTTPEnroller) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	return h.post(ctx, "/enroll/bootstrap", map[string]string{
		"token": token,
		"csr":   base64.StdEncoding.EncodeToString(csrDER),
	})
}

// EnrollRenewal posts the CSR to the renewal endpoint.
func (h *HTTPEnroller) EnrollRenewal(ctx context.Context, csrDER []byte) ([]byte, error) {
	return h.post(ctx, "/enroll/renewal", map[string]string{
		"csr": base64.StdEncoding.EncodeToString(csrDER),
	})
}

func (h *HTTPEnroller) post(ctx context.Context, path string, body map[string]string) ([]byte, error) {
	endpoint, err := h.endpoint(path)
	if err != nil {
		return nil, err
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Announce the agent's version + protocol so the control plane can record the
	// version and make a documented compatibility decision across a rolling upgrade
	// (SCHEMA-003).
	protocol.SetAgentHeaders(req.Header, buildinfo.Version())
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent: enrollment request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollBody))
	if err != nil {
		return nil, err
	}
	var out struct {
		Certificate string `json:"certificate"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("agent: decode enrollment response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: enrollment failed (status %d): %s", resp.StatusCode, out.Error)
	}
	return []byte(out.Certificate), nil
}

func (h *HTTPEnroller) endpoint(path string) (string, error) {
	if h.err != nil {
		return "", h.err
	}
	if h.base == nil {
		return "", errors.New("agent: enrollment base URL is not configured")
	}
	return h.base.JoinPath(strings.TrimPrefix(path, "/")).String(), nil
}

func validateEnrollmentBaseURL(raw string, client *http.Client, allowLoopbackDevHTTP bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("agent: enrollment URL is required")
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("agent: parse enrollment URL: %w", err)
	}
	if !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("agent: enrollment URL must be absolute, got %q", raw)
	}
	switch base.Scheme {
	case "https":
		if client == nil {
			return nil, errors.New("agent: enrollment HTTPS client must be explicit and CA-pinned")
		}
	case "http":
		if !allowLoopbackDevHTTP || !isLoopbackHost(base.Hostname()) {
			return nil, errors.New("agent: enrollment URL must be https with a CA-pinned client; http is allowed only for explicit loopback development")
		}
	default:
		return nil, fmt.Errorf("agent: enrollment URL scheme %q is not supported", base.Scheme)
	}
	return base, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
