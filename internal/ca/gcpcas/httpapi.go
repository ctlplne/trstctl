// SPDX-License-Identifier: BUSL-1.1

package gcpcas

import (
	"bytes"
	"context"
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

// HTTPConfig configures the production Google Cloud CAS REST transport.
type HTTPConfig struct {
	Endpoint    string
	BearerToken []byte
	HTTPClient  cloudhttp.Doer
	Timeout     time.Duration
}

// HTTPAPI implements the public CAS v1 caPools.certificates.create method.
type HTTPAPI struct {
	endpoint string
	token    []byte
	doer     cloudhttp.Doer
	timeout  time.Duration
}

var _ API = (*HTTPAPI)(nil)

func NewHTTPAPI(cfg HTTPConfig) (*HTTPAPI, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://privateca.googleapis.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("gcpcas: HTTP endpoint must be an absolute URL")
	}
	if len(cfg.BearerToken) == 0 {
		return nil, errors.New("gcpcas: bearer token is required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		if err := ca.ValidateExternalCAEndpoint("gcpcas", endpoint, ca.HTTPClientConfig{}); err != nil {
			return nil, err
		}
		doer = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPAPI{endpoint: endpoint, token: secrettext.Clone(cfg.BearerToken), doer: doer, timeout: timeout}, nil
}

// Destroy erases the short-lived OAuth bearer and drops idle sockets.
func (a *HTTPAPI) Destroy() {
	secret.Wipe(a.token)
	if client, ok := a.doer.(*http.Client); ok {
		client.CloseIdleConnections()
	}
}

func (a *HTTPAPI) CreateCertificate(ctx context.Context, in CreateCertificateInput) (Certificate, error) {
	parent := strings.Trim(strings.TrimSpace(in.Parent), "/")
	if parent == "" {
		return Certificate{}, errors.New("gcpcas: CA pool parent is required")
	}
	query := url.Values{}
	query.Set("certificateId", in.CertificateID)
	query.Set("requestId", in.RequestID)
	endpoint := a.endpoint + "/v1/" + parent + "/certificates?" + query.Encode()
	payload := struct {
		PEMCSR   secretjson.StringBytes `json:"pemCsr"`
		Lifetime string                 `json:"lifetime"`
	}{PEMCSR: secretjson.StringBytes(in.PemCSR), Lifetime: durationJSON(in.Lifetime)}
	body, err := json.Marshal(payload)
	if err != nil {
		return Certificate{}, err
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Certificate{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", a.token))
	req.Header.Set("Content-Type", "application/json")
	var out Certificate
	if err := cloudhttp.JSON(a.doer, req, &out, cloudhttp.WithTimeout(a.timeout)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Certificate{}, err
		}
		var statusErr *cloudhttp.StatusError
		if errors.As(err, &statusErr) {
			return Certificate{}, fmt.Errorf("gcpcas: create certificate: status %d", statusErr.StatusCode)
		}
		return Certificate{}, errors.New("gcpcas: create certificate request failed")
	}
	return out, nil
}

func durationJSON(d time.Duration) string {
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}
