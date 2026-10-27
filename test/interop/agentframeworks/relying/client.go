// SPDX-License-Identifier: BUSL-1.1

package relying

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client reads what a relying service needs from trstctl's API with a token
// scoped to agents:read.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// NewClient builds a client for the trstctl API at baseURL. caPEM, when set, is
// the only CA trusted for the API's TLS certificate.
func NewClient(baseURL, token string, caPEM []byte) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("relying: the trstctl URL must be https")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("relying: a trstctl API token is required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("relying: the trstctl CA file holds no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		token: strings.TrimSpace(token),
		http:  &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}, nil
}

// CredentialStatus is GET /api/v1/agent-delegation/credential-status.
type CredentialStatus struct {
	CredentialID        string `json:"credential_id"`
	Found               bool   `json:"found"`
	Status              string `json:"status"`
	CredentialSHA256    string `json:"credential_sha256"`
	DirectiveID         string `json:"directive_id"`
	RevocationReason    string `json:"revocation_reason"`
	RevocationEvidenced bool   `json:"revocation_evidenced"`
}

// IssuingCA is GET /api/v1/agent-delegation/issuing-ca.
type IssuingCA struct {
	TenantID       string `json:"tenant_id"`
	CertificatePEM string `json:"certificate_pem"`
	CertificateDER []byte `json:"certificate_der"`
	SPKISHA256     string `json:"spki_sha256"`
}

// RootAnchor is one entry of GET /api/v1/agent-delegation/root-anchors.
type RootAnchor struct {
	KeyID       string `json:"key_id"`
	PublicDER   []byte `json:"public_der"`
	AuthRef     string `json:"auth_ref"`
	Provisioned bool   `json:"provisioned"`
}

// CredentialStatus reads a credential's status.
func (c *Client) CredentialStatus(ctx context.Context, credentialID string) (CredentialStatus, error) {
	var out CredentialStatus
	err := c.get(ctx, "/api/v1/agent-delegation/credential-status?credential_id="+url.QueryEscape(credentialID), &out)
	if err == nil && out.CredentialID != credentialID {
		err = errors.New("relying: the status answer names another credential")
	}
	return out, err
}

// Chain reads a credential's delegation chain, root first.
func (c *Client) Chain(ctx context.Context, credentialID string) ([][]byte, error) {
	var out struct {
		CredentialID string   `json:"credential_id"`
		Records      [][]byte `json:"records"`
	}
	if err := c.get(ctx, "/api/v1/agent-delegation/chain?credential_id="+url.QueryEscape(credentialID), &out); err != nil {
		return nil, err
	}
	if out.CredentialID != credentialID {
		return nil, errors.New("relying: the chain answer names another credential")
	}
	return out.Records, nil
}

// IssuingCA reads the tenant's agent issuing CA.
func (c *Client) IssuingCA(ctx context.Context) (IssuingCA, error) {
	var out IssuingCA
	return out, c.get(ctx, "/api/v1/agent-delegation/issuing-ca", &out)
}

// RootAnchors reads the tenant's delegation root anchors.
func (c *Client) RootAnchors(ctx context.Context) ([]RootAnchor, error) {
	var out struct {
		Anchors []RootAnchor `json:"anchors"`
	}
	return out.Anchors, c.get(ctx, "/api/v1/agent-delegation/root-anchors", &out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("relying: trstctl is unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relying: trstctl answered %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
