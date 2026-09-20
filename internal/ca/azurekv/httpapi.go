// SPDX-License-Identifier: BUSL-1.1

package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const keyVaultAPIVersion = "7.4"

// HTTPConfig configures the Azure Key Vault Certificates REST transport.
type HTTPConfig struct {
	BearerToken []byte
	HTTPClient  cloudhttp.Doer
	Timeout     time.Duration
}

// HTTPAPI implements the Key Vault certificate create/pending/get wire calls.
// The configured vault URL remains part of every API input so one client cannot
// silently redirect an authority to a different vault.
type HTTPAPI struct {
	token        []byte
	doer         cloudhttp.Doer
	timeout      time.Duration
	customClient bool
}

var _ API = (*HTTPAPI)(nil)

func NewHTTPAPI(cfg HTTPConfig) (*HTTPAPI, error) {
	if len(cfg.BearerToken) == 0 {
		return nil, errors.New("azurekv: bearer token is required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPAPI{token: secrettext.Clone(cfg.BearerToken), doer: doer, timeout: timeout, customClient: cfg.HTTPClient != nil}, nil
}

// Destroy erases the short-lived Entra bearer and drops idle sockets.
func (a *HTTPAPI) Destroy() {
	secret.Wipe(a.token)
	if client, ok := a.doer.(*http.Client); ok {
		client.CloseIdleConnections()
	}
}

func (a *HTTPAPI) CreateCertificate(ctx context.Context, in CreateCertificateInput) (CertificateOperation, error) {
	months := int(in.Lifetime / (30 * 24 * time.Hour))
	if months < 1 {
		months = 1
	}
	payload := map[string]any{
		"policy": map[string]any{
			"x509_props": map[string]any{
				"subject": in.Subject, "sans": map[string]any{"dns_names": in.DNSNames}, "validity_months": months,
			},
			"issuer": map[string]any{"name": "Unknown"},
		},
		// Compatible certificate gateways can consume the caller-owned CSR on
		// this extension field. Native Key Vault's Unknown issuer flow exposes
		// the CSR from /pending and is completed through /pending/merge.
		"csr": secretjson.StringBytes(in.Csr),
	}
	var out certificateOperationEnvelope
	path := "/certificates/" + url.PathEscape(in.CertificateName) + "/create"
	if err := a.doJSON(ctx, http.MethodPut, in.VaultBaseURL, path, payload, &out); err != nil {
		return CertificateOperation{}, err
	}
	return out.operation(), nil
}

func (a *HTTPAPI) GetCertificateOperation(ctx context.Context, vaultBaseURL, certName string) (CertificateOperation, error) {
	var out certificateOperationEnvelope
	path := "/certificates/" + url.PathEscape(certName) + "/pending"
	if err := a.doJSON(ctx, http.MethodGet, vaultBaseURL, path, nil, &out); err != nil {
		return CertificateOperation{}, err
	}
	return out.operation(), nil
}

func (a *HTTPAPI) GetCertificate(ctx context.Context, vaultBaseURL, certName string) (Certificate, error) {
	var out struct {
		Cer   string   `json:"cer"`
		Chain []string `json:"chain,omitempty"`
	}
	path := "/certificates/" + url.PathEscape(certName)
	if err := a.doJSON(ctx, http.MethodGet, vaultBaseURL, path, nil, &out); err != nil {
		return Certificate{}, err
	}
	leaf, err := decodeKeyVaultDER(out.Cer)
	if err != nil {
		return Certificate{}, fmt.Errorf("azurekv: decode certificate: %w", err)
	}
	chain := make([][]byte, 0, len(out.Chain))
	for _, encoded := range out.Chain {
		der, err := decodeKeyVaultDER(encoded)
		if err != nil {
			return Certificate{}, fmt.Errorf("azurekv: decode certificate chain: %w", err)
		}
		chain = append(chain, der)
	}
	return Certificate{Cer: leaf, Chain: chain}, nil
}

type certificateOperationEnvelope struct {
	Status string `json:"status"`
}

func (e certificateOperationEnvelope) operation() CertificateOperation {
	status := e.Status
	switch strings.ToLower(status) {
	case "inprogress":
		status = StatusInProgress
	case "completed":
		status = StatusCompleted
	case "failed", "cancelled", "canceled":
		status = StatusFailed
	default:
		status = StatusFailed
	}
	return CertificateOperation{Status: status, Error: "provider operation failed"}
}

func (a *HTTPAPI) doJSON(ctx context.Context, method, vaultBaseURL, path string, body, out any) error {
	base := strings.TrimRight(strings.TrimSpace(vaultBaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("azurekv: vault URL must be absolute")
	}
	if !a.customClient {
		if err := ca.ValidateExternalCAEndpoint("azurekv", base, ca.HTTPClientConfig{}); err != nil {
			return err
		}
	}
	query := url.Values{"api-version": {keyVaultAPIVersion}}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	defer secret.Wipe(payload)
	req, err := http.NewRequestWithContext(ctx, method, base+path+"?"+query.Encode(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", a.token))
	req.Header.Set("Content-Type", "application/json")
	if err := cloudhttp.JSON(a.doer, req, out, cloudhttp.WithTimeout(a.timeout)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		var statusErr *cloudhttp.StatusError
		if errors.As(err, &statusErr) {
			return fmt.Errorf("azurekv: %s: status %d", method, statusErr.StatusCode)
		}
		return fmt.Errorf("azurekv: %s request failed", method)
	}
	return nil
}

func decodeKeyVaultDER(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("empty cer")
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if der, err := encoding.DecodeString(encoded); err == nil {
			return der, nil
		}
	}
	return nil, errors.New("cer is not base64/base64url")
}
