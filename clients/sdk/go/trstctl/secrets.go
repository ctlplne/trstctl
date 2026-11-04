// SPDX-License-Identifier: MPL-2.0

package trstctl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// ---- Secrets store, PKI secrets and revocation ------------------------------
//
// The same calls the Python and Java SDKs make. A secret's value is
// caller-owned []byte on the way in and SDK-returned []byte on the way out:
// the SDK wipes its own request and response copies, and the caller wipes
// what it is handed.

// SecretMeta is a stored secret's metadata (never its value).
type SecretMeta struct {
	Name      string     `json:"name"`
	Version   int        `json:"version"`
	OwnerID   string     `json:"owner_id,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// SecretValue is a stored secret read back. Wipe Value when done with it.
type SecretValue struct {
	Name    string
	Version int
	Value   []byte
}

// PKISecret is a short-lived certificate the PKI secrets engine issued. When
// the server generated the key (the deprecated common-name mode) PrivateKey
// holds it as PEM; wipe it when done.
type PKISecret struct {
	CertificateID string
	Serial        string
	CommonName    string
	Certificate   string
	PrivateKey    []byte
}

// RevocationResult is a bulk revocation's outcome: per certificate, revoked,
// queued for an external CA, skipped or failed.
type RevocationResult struct {
	TotalMatched int `json:"total_matched"`
	TotalRevoked int `json:"total_revoked"`
	TotalQueued  int `json:"total_queued"`
	TotalSkipped int `json:"total_skipped"`
	TotalFailed  int `json:"total_failed"`
	Items        []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	} `json:"items"`
}

// secretText marshals caller-owned bytes as a JSON string without first
// copying them into an immutable Go string.
type secretText []byte

func (s secretText) MarshalJSON() ([]byte, error) {
	// json.Marshal of a []byte would base64-encode it; the API takes text.
	var out []byte
	out = append(out, '"')
	for _, b := range s {
		switch {
		case b == '"' || b == '\\':
			out = append(out, '\\', b)
		case b < 0x20:
			const hex = "0123456789abcdef"
			out = append(out, '\\', 'u', '0', '0', hex[b>>4], hex[b&0xf])
		default:
			out = append(out, b)
		}
	}
	return append(out, '"'), nil
}

func secretPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("trstctl: secret name is empty")
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return "/api/v1/secrets/store/" + strings.Join(parts, "/"), nil
}

// CreateSecret stores a new secret (POST /api/v1/secrets/store).
func (c *Client) CreateSecret(ctx context.Context, name string, value []byte) (*SecretMeta, error) {
	return c.CreateSecretKeyed(ctx, name, value, "")
}

// CreateSecretKeyed is CreateSecret with a caller-supplied Idempotency-Key.
func (c *Client) CreateSecretKeyed(ctx context.Context, name string, value []byte, idempotencyKey string) (*SecretMeta, error) {
	var out SecretMeta
	body := struct {
		Name  string     `json:"name"`
		Value secretText `json:"value"`
	}{name, value}
	opts := mutationRequest(body, idempotencyKey, http.StatusCreated)
	if _, err := c.doStatus(ctx, http.MethodPost, "/api/v1/secrets/store", opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSecret reads a secret's current value (GET /api/v1/secrets/store/{name}).
func (c *Client) GetSecret(ctx context.Context, name string) (*SecretValue, error) {
	path, err := secretPath(name)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Name    string          `json:"name"`
		Version int             `json:"version"`
		Value   json.RawMessage `json:"value"`
	}
	opts := requestOptions{expectedStatuses: []int{http.StatusOK}, requireBody: true, sensitive: true, noRedirect: true}
	if _, err := c.doStatus(ctx, http.MethodGet, path, opts, &raw); err != nil {
		return nil, err
	}
	defer wipeBytes(raw.Value)
	value, err := unquoteSecret(raw.Value)
	if err != nil {
		return nil, err
	}
	return &SecretValue{Name: raw.Name, Version: raw.Version, Value: value}, nil
}

// RotateSecret stores a new version of a secret (PUT /api/v1/secrets/store/{name}).
func (c *Client) RotateSecret(ctx context.Context, name string, value []byte) (*SecretMeta, error) {
	return c.RotateSecretKeyed(ctx, name, value, "")
}

// RotateSecretKeyed is RotateSecret with a caller-supplied Idempotency-Key.
func (c *Client) RotateSecretKeyed(ctx context.Context, name string, value []byte, idempotencyKey string) (*SecretMeta, error) {
	path, err := secretPath(name)
	if err != nil {
		return nil, err
	}
	var out SecretMeta
	body := struct {
		Value secretText `json:"value"`
	}{value}
	if _, err := c.doStatus(ctx, http.MethodPut, path, mutationRequest(body, idempotencyKey, http.StatusOK), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSecret deletes a secret (DELETE /api/v1/secrets/store/{name}).
func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	return c.DeleteSecretKeyed(ctx, name, "")
}

// DeleteSecretKeyed is DeleteSecret with a caller-supplied Idempotency-Key.
func (c *Client) DeleteSecretKeyed(ctx context.Context, name, idempotencyKey string) error {
	path, err := secretPath(name)
	if err != nil {
		return err
	}
	opts := requestOptions{idempotencyKey: idempotencyKey, expectedStatuses: []int{http.StatusNoContent}}
	_, err = c.doStatus(ctx, http.MethodDelete, path, opts, nil)
	return err
}

// IssuePKISecret has the PKI secrets engine issue a short-lived certificate
// for commonName (POST /api/v1/secrets/pki). In this mode the server generates
// the key and returns it; a tenant may refuse server-side key generation.
func (c *Client) IssuePKISecret(ctx context.Context, commonName string, ttl time.Duration) (*PKISecret, error) {
	return c.IssuePKISecretKeyed(ctx, commonName, ttl, "")
}

// IssuePKISecretKeyed is IssuePKISecret with a caller-supplied Idempotency-Key.
func (c *Client) IssuePKISecretKeyed(ctx context.Context, commonName string, ttl time.Duration, idempotencyKey string) (*PKISecret, error) {
	body := map[string]any{"common_name": commonName, "ttl_seconds": int(ttl / time.Second)}
	var raw struct {
		CertificateID string          `json:"certificate_id"`
		Serial        string          `json:"serial"`
		CommonName    string          `json:"common_name"`
		Certificate   string          `json:"certificate"`
		PrivateKey    json.RawMessage `json:"private_key"`
	}
	if _, err := c.doStatus(ctx, http.MethodPost, "/api/v1/secrets/pki", mutationRequest(body, idempotencyKey, http.StatusOK, http.StatusCreated), &raw); err != nil {
		return nil, err
	}
	defer wipeBytes(raw.PrivateKey)
	out := &PKISecret{CertificateID: raw.CertificateID, Serial: raw.Serial, CommonName: raw.CommonName, Certificate: raw.Certificate}
	if len(raw.PrivateKey) > 0 && string(raw.PrivateKey) != "null" {
		key, err := unquoteSecret(raw.PrivateKey)
		if err != nil {
			return nil, err
		}
		out.PrivateKey = key
	}
	return out, nil
}

// RevokeCertificates revokes certificates by inventory ID
// (POST /api/v1/certificates/bulk-revoke) with an RFC 5280 reason such as
// "superseded" or "keyCompromise".
func (c *Client) RevokeCertificates(ctx context.Context, certificateIDs []string, reason string) (*RevocationResult, error) {
	return c.RevokeCertificatesKeyed(ctx, certificateIDs, reason, "")
}

// RevokeCertificatesKeyed is RevokeCertificates with a caller-supplied
// Idempotency-Key.
func (c *Client) RevokeCertificatesKeyed(ctx context.Context, certificateIDs []string, reason, idempotencyKey string) (*RevocationResult, error) {
	if len(certificateIDs) == 0 {
		return nil, errors.New("trstctl: no certificate IDs to revoke")
	}
	body := map[string]any{"certificate_ids": certificateIDs, "reason": reason}
	var out RevocationResult
	if _, err := c.doStatus(ctx, http.MethodPost, "/api/v1/certificates/bulk-revoke", mutationRequest(body, idempotencyKey, http.StatusOK), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// unquoteSecret decodes a JSON string into a fresh byte slice the caller
// owns, without passing through an immutable Go string.
func unquoteSecret(raw json.RawMessage) ([]byte, error) {
	bad := errors.New("trstctl: a secret value in the response is not a JSON string")
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, bad
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		b := in[i]
		if b != '\\' {
			out = append(out, b)
			continue
		}
		if i++; i >= len(in) {
			wipeBytes(out)
			return nil, bad
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, n := hexRune(in[i+1:])
			if n == 0 {
				wipeBytes(out)
				return nil, bad
			}
			i += n
			if utf16.IsSurrogate(r) {
				if len(in) > i+2 && in[i+1] == '\\' && in[i+2] == 'u' {
					if low, m := hexRune(in[i+3:]); m != 0 {
						r = utf16.DecodeRune(r, low)
						i += 2 + m
					}
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			wipeBytes(out)
			return nil, bad
		}
	}
	return out, nil
}

// hexRune reads four hex digits; n is 4 on success and 0 otherwise.
func hexRune(b []byte) (rune, int) {
	if len(b) < 4 {
		return 0, 0
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, 0
		}
	}
	return r, 4
}
