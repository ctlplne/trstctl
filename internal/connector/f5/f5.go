// SPDX-License-Identifier: MPL-2.0

// Package f5 is the F5 BIG-IP deployment connector (S5.10), built from the
// connector SDK (S5.5). Unlike the file-plus-reload connectors, BIG-IP is an
// appliance reached over the iControl REST API (HTTPS). The connector uploads
// the certificate and key, installs them as crypto objects, and points the
// Client SSL profile at them. It runs only HTTP requests — least-privilege grant
// is net.dial to the BIG-IP host alone; no filesystem, no exec.
package f5

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secrettext"
)

// Connector deploys certificates to an F5 BIG-IP over iControl REST.
type Connector struct {
	baseURL string // the management base, e.g. "https://bigip.example"
	host    string // host[:port] of baseURL, for the net.dial grant
	profile string // the Client SSL profile to bind
	name    string // the crypto object base name (default: the profile)
	user    string
	pass    []byte
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithBasicAuthBytes keeps the authority-bearing password zeroizable until the
// final net/http authorization-header edge.
func WithBasicAuthBytes(user string, pass []byte) Option {
	return func(c *Connector) {
		c.user = user
		c.pass = append(c.pass[:0], pass...)
	}
}

// WithName sets the crypto object base name (default: the profile name).
func WithName(name string) Option { return func(c *Connector) { c.name = name } }

// New returns a connector that installs the certificate on the BIG-IP at baseURL
// and binds it to the Client SSL profile.
func New(baseURL, profile string, opts ...Option) *Connector {
	c := &Connector{baseURL: strings.TrimRight(baseURL, "/"), profile: profile, name: profile}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Connector) Close() {
	secret.Wipe(c.pass)
	c.pass = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "f5" }

// Capabilities declares the least privilege the connector needs: reach the
// BIG-IP host over the network. It never touches the filesystem or runs
// commands.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy uploads the certificate and key, installs them, and binds them to the
// Client SSL profile.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	certName := c.name + ".crt"
	keyName := c.name + ".key"

	if err := c.call(ctx, sb, http.MethodPost, "/mgmt/shared/file-transfer/uploads/"+certName, "application/octet-stream", dep.CertPEM); err != nil {
		return fmt.Errorf("f5: upload certificate: %w", err)
	}
	if err := c.call(ctx, sb, http.MethodPost, "/mgmt/shared/file-transfer/uploads/"+keyName, "application/octet-stream", dep.KeyPEM); err != nil {
		return fmt.Errorf("f5: upload key: %w", err)
	}
	if err := c.callJSON(ctx, sb, http.MethodPost, "/mgmt/tm/sys/crypto/cert", map[string]string{
		"command": "install", "name": certName, "from-local-file": "/var/config/rest/downloads/" + certName,
	}); err != nil {
		return fmt.Errorf("f5: install certificate: %w", err)
	}
	if err := c.callJSON(ctx, sb, http.MethodPost, "/mgmt/tm/sys/crypto/key", map[string]string{
		"command": "install", "name": keyName, "from-local-file": "/var/config/rest/downloads/" + keyName,
	}); err != nil {
		return fmt.Errorf("f5: install key: %w", err)
	}
	if err := c.callJSON(ctx, sb, http.MethodPatch, "/mgmt/tm/ltm/profile/client-ssl/"+c.profile, map[string]any{
		"certKeyChain": []map[string]string{{"name": c.name, "cert": certName, "key": keyName}},
	}); err != nil {
		return fmt.Errorf("f5: bind to profile %q: %w", c.profile, err)
	}
	return nil
}

func (c *Connector) callJSON(ctx context.Context, sb connector.Sandbox, method, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	defer secret.Wipe(body)
	return c.call(ctx, sb, method, path, "application/json", body)
}

func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, path, contentType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if c.user != "" || len(c.pass) > 0 {
		req.Header.Set("Authorization", c.basicAuth())
	}
	resp, err := sb.Request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return nil
}

// basicAuth keeps the cleartext password byte-backed. Only the base64 HTTP
// header value crosses into a string at net/http's forced wire boundary.
func (c *Connector) basicAuth() string {
	raw := make([]byte, 0, len(c.user)+1+len(c.pass))
	raw = append(raw, c.user...)
	raw = append(raw, ':')
	raw = append(raw, c.pass...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	secret.Wipe(raw)
	defer secret.Wipe(encoded)
	return secrettext.Prefixed("Basic ", encoded)
}
