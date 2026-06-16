package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPSigner is a Signer that forwards CSRs to a trstctl control-plane issuance
// endpoint over HTTP and returns the issued certificate chain. It posts
// {"csr": base64(DER)} and expects {"certificate": "<PEM chain>"}. Only a CSR
// crosses the wire — never a private key.
type HTTPSigner struct {
	url    string
	client *http.Client
}

var _ Signer = (*HTTPSigner)(nil)

// NewHTTPSigner returns a signer posting to url (using client, or a default
// client when nil).
func NewHTTPSigner(url string, client *http.Client) *HTTPSigner {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPSigner{url: url, client: client}
}

// Sign forwards the CSR to the control plane and returns the issued chain.
func (s *HTTPSigner) Sign(ctx context.Context, csrDER []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(csrDER)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s: signer request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Certificate string `json:"certificate"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("k8s: signer status %d: %s", resp.StatusCode, out.Error)
	}
	return []byte(out.Certificate), nil
}
