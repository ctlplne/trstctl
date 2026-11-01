// SPDX-License-Identifier: MPL-2.0

// Package trstctlsign is a minimal client for trstctl's code-signing API. It
// signs a digest with a managed key, which never leaves trstctl's isolated
// signer, and reads the certificate chain configured for that key. Stock
// signing tools reach it through the Notation plugin and the PKCS #11 module
// in this module.
package trstctlsign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client talks to one trstctl control plane with an API token.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// ApprovalWait is how long SignDigest holds a request open while a signing
	// approval it needs is pending; zero stops at the first refusal.
	ApprovalWait time.Duration
	// ApprovalPoll is how often a pending approval is checked; zero means five
	// seconds.
	ApprovalPoll time.Duration
	// Pending, when set, is told once that the request waits for approval,
	// with trstctl's message naming the approval request.
	Pending func(message string)
}

// FromEnv reads TRSTCTL_URL, the token from TRSTCTL_TOKEN or the file named by
// TRSTCTL_TOKEN_FILE, and an optional PEM bundle of trusted roots for the
// control plane's TLS certificate from TRSTCTL_CA_FILE.
func FromEnv() (*Client, error) {
	token := strings.TrimSpace(os.Getenv("TRSTCTL_TOKEN"))
	if file := strings.TrimSpace(os.Getenv("TRSTCTL_TOKEN_FILE")); token == "" && file != "" {
		raw, err := os.ReadFile(file) // #nosec G304 -- the operator names the token file
		if err != nil {
			return nil, fmt.Errorf("read TRSTCTL_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		return nil, errors.New("set TRSTCTL_TOKEN (or TRSTCTL_TOKEN_FILE)")
	}
	client, err := NewClient(os.Getenv("TRSTCTL_URL"), token, os.Getenv("TRSTCTL_CA_FILE"))
	if err != nil {
		return nil, err
	}
	if client.ApprovalWait, err = ApprovalWaitFromEnv(); err != nil {
		return nil, err
	}
	return client, nil
}

// ApprovalWaitFromEnv reads TRSTCTL_APPROVAL_WAIT, a Go duration such as 15m;
// unset means ten minutes and 0 means do not wait.
func ApprovalWaitFromEnv() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv("TRSTCTL_APPROVAL_WAIT"))
	if raw == "" {
		return 10 * time.Minute, nil
	}
	wait, err := time.ParseDuration(raw)
	if err != nil || wait < 0 {
		return 0, fmt.Errorf("TRSTCTL_APPROVAL_WAIT %q is not a duration such as 15m", raw)
	}
	return wait, nil
}

// NewClient builds a client for one control plane and API token. caFile, when
// set, names PEM roots for the control plane's TLS certificate.
func NewClient(baseURL, token, caFile string) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	token = strings.TrimSpace(token)
	if base == "" || token == "" {
		return nil, errors.New("set TRSTCTL_URL and an API token")
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("TRSTCTL_URL %q is not an http(s) URL", base)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if file := strings.TrimSpace(caFile); file != "" {
		raw, err := os.ReadFile(file) // #nosec G304 -- the operator names the CA bundle
		if err != nil {
			return nil, fmt.Errorf("read TRSTCTL_CA_FILE: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("TRSTCTL_CA_FILE holds no PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &Client{BaseURL: base, Token: token, HTTP: &http.Client{Timeout: 60 * time.Second, Transport: transport}}, nil
}

// Signature is what the signer returned for one digest: ASN.1 DER for ECDSA,
// PKCS #1 v1.5 for RSA.
type Signature struct {
	Algorithm    string `json:"algorithm"`
	Signature    []byte `json:"signature"`
	PublicKeyDER []byte `json:"public_key_der"`
}

// KeyCertificate is the chain configured for a key.
type KeyCertificate struct {
	KeyID           string    `json:"key_id"`
	Algorithm       string    `json:"algorithm"`
	PublicKeyDER    []byte    `json:"public_key_der"`
	ChainPEM        string    `json:"chain_pem"`
	LeafFingerprint string    `json:"leaf_fingerprint"`
	NotAfter        time.Time `json:"not_after"`
	CodeSigningEKU  bool      `json:"code_signing_eku"`
}

// ChainDER returns the chain's certificates, leaf first.
func (k KeyCertificate) ChainDER() [][]byte {
	var out [][]byte
	for rest := []byte(k.ChainPEM); ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
}

// SignDigest asks trstctl to sign a SHA-256 digest with keyID.
//
// The idempotency key is derived from the key, the artifact type, the digest
// and the caller's credential, so a retry after a lost response returns the
// first signature rather than signing twice, and trstctl's exact signing
// approval — bound to the request and its idempotency key — is the same
// approval on every retry. Two callers with different credentials never share
// a key.
func (c *Client) SignDigest(ctx context.Context, keyID, artifactType string, digest []byte) (Signature, error) {
	if len(digest) != 32 {
		return Signature{}, fmt.Errorf("trstctl signs SHA-256 digests; got %d bytes", len(digest))
	}
	body, err := json.Marshal(map[string]any{"key_id": keyID, "artifact_type": artifactType, "digest": digest})
	if err != nil {
		return Signature{}, err
	}
	credential := sha256.Sum256([]byte(c.Token))
	request := sha256.New()
	for _, part := range [][]byte{[]byte(keyID), []byte(artifactType), digest, credential[:]} {
		request.Write(part)
		request.Write([]byte{0})
	}
	idempotencyKey := "trstctlsign-" + hex.EncodeToString(request.Sum(nil))
	var out Signature
	deadline := time.Now().Add(c.ApprovalWait)
	told := false
	for attempt := 1; ; attempt++ {
		err = c.do(ctx, http.MethodPost, "/api/v1/code-signing/sign", body, idempotencyKey, &out)
		var refused *APIError
		var wait time.Duration
		switch {
		case err == nil:
			return out, nil
		case errors.As(err, &refused) && refused.ApprovalPending():
			// The same request — same digest, same idempotency key — is what the
			// approver grants, so it is resent unchanged until the approval is
			// granted, refused or out of time.
			if !time.Now().Before(deadline) {
				return out, err
			}
			if !told && c.Pending != nil {
				c.Pending(refused.Message)
			}
			told, wait = true, c.ApprovalPoll
			if wait <= 0 {
				wait = 5 * time.Second
			}
		case errors.As(err, &refused) && refused.Status != http.StatusBadGateway &&
			refused.Status != http.StatusServiceUnavailable && refused.Status != http.StatusGatewayTimeout:
			return out, err
		case attempt >= 3:
			return out, err
		default:
			wait = time.Duration(attempt) * time.Second
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// KeyCertificate reads the chain configured for keyID.
func (c *Client) KeyCertificate(ctx context.Context, keyID string) (KeyCertificate, error) {
	var out KeyCertificate
	err := c.do(ctx, http.MethodGet, "/api/v1/code-signing/keys/"+url.PathEscape(keyID)+"/certificate", nil, "", &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, idempotencyKey string, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var problem struct {
			Detail string `json:"detail"`
			Title  string `json:"title"`
		}
		_ = json.Unmarshal(raw, &problem)
		msg := strings.TrimSpace(problem.Detail)
		if msg == "" {
			msg = strings.TrimSpace(problem.Title)
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	return json.Unmarshal(raw, out)
}

// APIError is a refusal from trstctl, for example a missing permission or a
// signing approval that was denied.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("trstctl refused (HTTP %d): %s", e.Status, e.Message)
}

// ApprovalPending reports whether trstctl holds the signature for an approval
// that is still pending: waiting can help. A denied, expired, consumed or
// superseded approval is final.
func (e *APIError) ApprovalPending() bool {
	return e.Status == http.StatusForbidden && strings.Contains(e.Message, "approval_required:") &&
		strings.Contains(e.Message, " awaits ")
}

// Denied reports whether trstctl refused the signature itself — the caller
// lacks the permission, or policy or a pending or denied approval stopped it —
// rather than failing to answer.
func (e *APIError) Denied() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}
