// SPDX-License-Identifier: MPL-2.0

// Package kemp is the Kemp LoadMaster deployment connector. It uses the HTTPS
// management API to upload a renewed certificate/key and bind it to a virtual
// service. The connector only asks for net.dial to the LoadMaster management
// host.
package kemp

import (
	"bytes"
	"context"
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

// Connector deploys certificates to a Kemp LoadMaster over HTTPS.
type Connector struct {
	baseURL string
	host    string
	token   []byte
}

var _ connector.Connector = (*Connector)(nil)

// New returns a Kemp connector using a bearer token held as wipeable bytes.
func New(baseURL string, token []byte) *Connector {
	c := &Connector{baseURL: strings.TrimRight(baseURL, "/"), token: append([]byte(nil), token...)}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	return c
}

// Close zeroizes the bearer token.
func (c *Connector) Close() {
	secret.Wipe(c.token)
	c.token = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "kemp" }

// Capabilities grants network access to the LoadMaster host only.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy uploads the renewed cert/key and binds it to the virtual service named
// by dep.Target.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	certName := dep.Target + "-trstctl"
	if err := c.call(ctx, sb, http.MethodPut, "/access/certificates/"+url.PathEscape(certName), certificateReq{
		Name:        certName,
		Certificate: dep.CertPEM,
		PrivateKey:  dep.KeyPEM,
	}); err != nil {
		return fmt.Errorf("kemp: upload certificate: %w", err)
	}
	if err := c.call(ctx, sb, http.MethodPatch, "/access/virtual-services/"+url.PathEscape(dep.Target)+"/certificate", bindReq{
		CertName: certName,
	}); err != nil {
		return fmt.Errorf("kemp: bind virtual service %q: %w", dep.Target, err)
	}
	return nil
}

type certificateReq struct {
	Name        string `json:"name"`
	Certificate []byte `json:"certificate_pem"`
	PrivateKey  []byte `json:"private_key_pem"`
}

type bindReq struct {
	CertName string `json:"cert_name"`
}

func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.token))
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
