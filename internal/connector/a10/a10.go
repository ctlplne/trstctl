// SPDX-License-Identifier: MPL-2.0

// Package a10 is the A10 Thunder/AX load-balancer deployment connector.
// It drives the appliance over an aXAPI-style HTTPS management API: authenticate,
// upload renewed certificate/key files, then bind the client-SSL template. The
// connector has only net.dial capability for the management host; no filesystem
// or process execution.
package a10

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector deploys certificates to an A10 load balancer over HTTPS.
type Connector struct {
	baseURL string
	host    string
	user    string
	pass    []byte
}

var _ connector.Connector = (*Connector)(nil)

// New returns an A10 connector for baseURL using the given aXAPI credentials.
// pass is copied as []byte so callers may wipe their buffer.
func New(baseURL, user string, pass []byte) *Connector {
	c := &Connector{baseURL: strings.TrimRight(baseURL, "/"), user: user, pass: append([]byte(nil), pass...)}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	return c
}

// Close zeroizes the stored aXAPI password.
func (c *Connector) Close() {
	secret.Wipe(c.pass)
	c.pass = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "a10" }

// Capabilities grants network access to the A10 management host only.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy uploads the renewed cert/key and binds the named client-SSL template.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("a10: %w", err)
	}
	certFile := dep.Target + ".crt"
	keyFile := dep.Target + ".key"
	if err := c.upload(ctx, sb, token, "ssl-cert", certFile, dep.CertPEM); err != nil {
		return fmt.Errorf("a10: upload certificate: %w", err)
	}
	if err := c.upload(ctx, sb, token, "ssl-key", keyFile, dep.KeyPEM); err != nil {
		return fmt.Errorf("a10: upload key: %w", err)
	}
	if err := c.bind(ctx, sb, token, dep.Target, certFile, keyFile); err != nil {
		return fmt.Errorf("a10: bind client-ssl template %q: %w", dep.Target, err)
	}
	return nil
}

func (c *Connector) login(ctx context.Context, sb connector.Sandbox) (string, error) {
	data, err := c.call(ctx, sb, http.MethodPost, "/axapi/v3/auth", "", map[string]any{
		"credentials": map[string]string{"username": c.user, "password": string(c.pass)},
	})
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	var out struct {
		AuthResponse struct {
			Signature string `json:"signature"`
		} `json:"authresponse"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("login: decode response: %w", err)
	}
	if strings.TrimSpace(out.AuthResponse.Signature) == "" {
		return "", fmt.Errorf("login: response missing authresponse.signature")
	}
	return out.AuthResponse.Signature, nil
}

func (c *Connector) upload(ctx context.Context, sb connector.Sandbox, token, kind, filename string, content []byte) error {
	_, err := c.call(ctx, sb, http.MethodPost, "/axapi/v3/file/"+kind, token, map[string]any{
		kind: map[string]string{
			"file":         filename,
			"file-content": base64.StdEncoding.EncodeToString(content),
		},
	})
	return err
}

func (c *Connector) bind(ctx context.Context, sb connector.Sandbox, token, template, certFile, keyFile string) error {
	_, err := c.call(ctx, sb, http.MethodPut, "/axapi/v3/slb/template/client-ssl/"+url.PathEscape(template), token, map[string]any{
		"client-ssl": map[string]string{"name": template, "cert": certFile, "key": keyFile},
	})
	return err
}

func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, path, token string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "A10 "+token)
	}
	resp, err := sb.Request(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}
