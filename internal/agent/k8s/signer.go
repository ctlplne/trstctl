// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const signerResponseLimit = 1 << 20

// HTTPSigner is a Signer that forwards CSRs to a trstctl control-plane issuance
// endpoint over HTTP and returns the issued certificate chain. It posts both
// {"csr": base64(DER)} for older adapters and {"csr_pem": "<PEM CSR>"} for the
// served trstctl issuance routes, and accepts either {"certificate": "..."} or
// {"certificate_pem": "..."} in response. Only a CSR crosses the wire — never a
// private key.
type HTTPSigner struct {
	url         string
	client      *http.Client
	bearerToken []byte
}

var _ Signer = (*HTTPSigner)(nil)

// HTTPSignerOption configures an HTTPSigner.
type HTTPSignerOption func(*HTTPSigner)

// WithBearerToken adds the API-token credential the served trstctl issuance
// routes require. The caller owns wiping token when the signer stops.
func WithBearerToken(token []byte) HTTPSignerOption {
	return func(s *HTTPSigner) {
		s.bearerToken = token
	}
}

// NewHTTPSigner returns a signer posting to url (using client, or a default
// client when nil).
func NewHTTPSigner(url string, client *http.Client, opts ...HTTPSignerOption) *HTTPSigner {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	s := &HTTPSigner{url: url, client: client}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Sign forwards the CSR to the control plane and returns the issued chain.
func (s *HTTPSigner) Sign(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
	if ttl < time.Second || ttl%time.Second != 0 {
		return nil, fmt.Errorf("k8s: requested certificate lifetime must be positive whole seconds")
	}
	body, err := json.Marshal(map[string]any{
		"csr":         base64.StdEncoding.EncodeToString(csrDER),
		"csr_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ttl_seconds": int64(ttl / time.Second),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", signerIdempotencyKey(s.url, csrDER, ttl))
	if len(s.bearerToken) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(s.bearerToken))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: signer request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, signerResponseLimit))
	if err != nil {
		return nil, fmt.Errorf("k8s: read signer response: %w", err)
	}
	var out struct {
		Certificate    string `json:"certificate"`
		CertificatePEM string `json:"certificate_pem"`
		Error          string `json:"error"`
	}
	if resp.StatusCode/100 != 2 {
		if err := json.Unmarshal(data, &out); err != nil {
			out.Error = ""
		}
		return nil, fmt.Errorf("k8s: signer status %d: %s", resp.StatusCode, signerErrorContext(data, out.Error))
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("k8s: decode signer response: %w", err)
	}
	cert := out.Certificate
	if strings.TrimSpace(cert) == "" {
		cert = out.CertificatePEM
	}
	if strings.TrimSpace(cert) == "" {
		return nil, fmt.Errorf("k8s: signer response missing certificate")
	}
	return []byte(cert), nil
}

func signerIdempotencyKey(endpoint string, csrDER []byte, ttl time.Duration) string {
	// Idempotency is scoped by tenant, not by CA endpoint. Bind the selected
	// authority as well as the CSR and lifetime to prevent a retry against a
	// different CA from receiving the original authority's certificate.
	identity := endpoint + "\x00" + crypto.SHA256Hex(csrDER) + "\x00" + strconv.FormatInt(int64(ttl/time.Second), 10)
	return "k8s-cert-manager-" + crypto.SHA256Hex([]byte(identity))
}

func signerErrorContext(data []byte, apiError string) string {
	if strings.TrimSpace(apiError) != "" {
		return apiError
	}
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return "empty response body"
	}
	const max = 512
	if len(msg) > max {
		msg = msg[:max] + "...(truncated)"
	}
	return msg
}
