package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/protocol"
)

const maxEnrollBody = 1 << 20

// HTTPEnroller is an Enroller that talks to a control-plane enrollment endpoint
// (enroll.Handler) over HTTP. It submits CSRs (never keys) and returns the issued
// certificate chain.
type HTTPEnroller struct {
	baseURL string
	client  *http.Client
}

var _ Enroller = (*HTTPEnroller)(nil)

// NewHTTPEnroller returns an enroller posting to baseURL (using client, or a
// default client when nil).
func NewHTTPEnroller(baseURL string, client *http.Client) *HTTPEnroller {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPEnroller{baseURL: baseURL, client: client}
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
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path, bytes.NewReader(buf))
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
