// Package digicert is the DigiCert CertCentral CA plugin (F4, sprint S4.7), built
// from the CA-plugin template (internal/ca/catemplate): it implements only the
// CA-specific Backend and the template contributes the rest. It speaks the
// DigiCert CertCentral Services API — submit an order with the CSR, poll the
// order until it is issued, then download the PEM chain — authenticating with the
// X-DC-DEVKEY header.
//
// CSRs are PEM-encoded for the API with encoding/pem; the package holds no
// crypto/* (AN-3). It carries no signing key — DigiCert custodies issuance — so
// AN-4 is not implicated; on the platform it runs behind ca.IssuanceService for
// idempotency (AN-5) and the outbox (AN-6).
package digicert

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/ca/catemplate"
)

const (
	defaultProduct = "ssl_plus"
	defaultTTL     = 90 * 24 * time.Hour
	apiBase        = "/services/v2"
	pollInterval   = 500 * time.Millisecond
	maxPolls       = 60
	maxBody        = 1 << 20
)

// backend talks the CertCentral Services API. It is the only CA-specific code;
// the template supplies the ca.CA behaviour.
type backend struct {
	name    string
	baseURL string
	apiKey  string
	product string
	client  *http.Client
}

// Option configures the plugin.
type Option func(*backend)

// WithHTTPClient sets the HTTP client (for custom timeouts or transport).
func WithHTTPClient(c *http.Client) Option {
	return func(b *backend) {
		if c != nil {
			b.client = c
		}
	}
}

// WithProduct sets the CertCentral product identifier (default "ssl_plus").
func WithProduct(product string) Option {
	return func(b *backend) {
		if product != "" {
			b.product = product
		}
	}
}

// New builds the DigiCert plugin for the CertCentral API at baseURL (for example
// https://www.digicert.com) authenticating with apiKey. The returned
// *catemplate.Plugin is a ca.CA.
func New(name, baseURL, apiKey string, opts ...Option) *catemplate.Plugin {
	b := &backend{name: name, baseURL: baseURL, apiKey: apiKey, product: defaultProduct, client: http.DefaultClient}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.name }

// Issue runs the CertCentral issuance flow: submit the order, await issuance,
// download the chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("digicert: at least one DNS name is required")
	}
	orderID, certID, err := b.submitOrder(ctx, req)
	if err != nil {
		return nil, err
	}
	certID, err = b.awaitIssued(ctx, orderID, certID)
	if err != nil {
		return nil, err
	}
	return b.downloadChain(ctx, certID)
}

// submitOrder POSTs the order with the CSR (PEM) and returns the order and (if
// the order is issued without approval) certificate ids.
func (b *backend) submitOrder(ctx context.Context, req ca.IssueRequest) (orderID, certID int, err error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	days := int(ttl / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR})
	payload := map[string]any{
		"certificate": map[string]any{
			"common_name":     req.DNSNames[0],
			"dns_names":       req.DNSNames,
			"csr":             string(csrPEM),
			"signature_hash":  "sha256",
			"server_platform": map[string]any{"id": -1},
		},
		"order_validity": map[string]any{"days": days},
		"skip_approval":  true,
		"payment_method": "balance",
	}
	var out struct {
		ID            int `json:"id"`
		CertificateID int `json:"certificate_id"`
	}
	if err := b.do(ctx, http.MethodPost, b.orderURL(b.product), payload, &out); err != nil {
		return 0, 0, err
	}
	if out.ID == 0 {
		return 0, 0, fmt.Errorf("digicert: order response carried no order id")
	}
	return out.ID, out.CertificateID, nil
}

// awaitIssued polls the order until it reaches the issued status, returning the
// certificate id. CertCentral OV/EV orders may require validation before issuing;
// the bounded poll covers a double's immediate issuance and a brief real delay,
// while the outbox (AN-6) absorbs longer waits on the platform.
func (b *backend) awaitIssued(ctx context.Context, orderID, certID int) (int, error) {
	for attempt := 0; attempt < maxPolls; attempt++ {
		var info struct {
			Status      string `json:"status"`
			Certificate struct {
				ID int `json:"id"`
			} `json:"certificate"`
		}
		if err := b.do(ctx, http.MethodGet, b.orderURL(strconv.Itoa(orderID)), nil, &info); err != nil {
			return 0, err
		}
		cid := certID
		if info.Certificate.ID != 0 {
			cid = info.Certificate.ID
		}
		switch info.Status {
		case "issued":
			if cid == 0 {
				return 0, fmt.Errorf("digicert: order %d issued but no certificate id", orderID)
			}
			return cid, nil
		case "rejected", "canceled":
			return 0, fmt.Errorf("digicert: order %d %s", orderID, info.Status)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	return 0, fmt.Errorf("digicert: order %d was not issued within the polling window", orderID)
}

// downloadChain fetches the full PEM chain (pem_all) for the certificate.
func (b *backend) downloadChain(ctx context.Context, certID int) ([]byte, error) {
	url := b.baseURL + apiBase + "/certificate/" + strconv.Itoa(certID) + "/download/format/pem_all"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-DC-DEVKEY", b.apiKey)
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("digicert: download certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, apiError(resp.StatusCode, data)
	}
	return data, nil
}

func (b *backend) orderURL(suffix string) string {
	return b.baseURL + apiBase + "/order/certificate/" + suffix
}

// do issues a JSON request, decoding the response into out (when non-nil) and
// mapping a CertCentral error envelope to a Go error.
func (b *backend) do(ctx context.Context, method, url string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	httpReq.Header.Set("X-DC-DEVKEY", b.apiKey)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("digicert: %s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("digicert: decode response: %w", err)
		}
	}
	return nil
}

// apiError maps a CertCentral {"errors":[{code,message}]} envelope to an error.
func apiError(status int, data []byte) error {
	var env struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &env); err == nil && len(env.Errors) > 0 {
		return fmt.Errorf("digicert: api error %d: %s: %s", status, env.Errors[0].Code, env.Errors[0].Message)
	}
	return fmt.Errorf("digicert: api error %d", status)
}
