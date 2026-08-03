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
	// D4: the certificate object name carries the fingerprint, so a second
	// deployment does not overwrite the first. The predecessor stays on the
	// LoadMaster and Rollback can bind the virtual service back to it without
	// the control plane holding a key it deliberately does not have.
	certName := connector.DeployedObjectName(dep.Target+"-trstctl", dep.Fingerprint)
	if err := c.call(ctx, sb, http.MethodPut, "/access/certificates/"+url.PathEscape(certName), certificateReq{
		Name:        certName,
		Certificate: dep.CertPEM,
		PrivateKey:  dep.KeyPEM,
	}); err != nil {
		return fmt.Errorf("kemp: upload certificate: %w", err)
	}
	if err := c.bind(ctx, sb, dep.Target, certName); err != nil {
		return fmt.Errorf("kemp: bind virtual service %q: %w", dep.Target, err)
	}
	return nil
}

// Rollback re-binds a virtual service to an already-uploaded predecessor
// certificate (epic D4). Nothing is uploaded — the object is there because the
// deploy that installed it named it after its own fingerprint.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" || strings.TrimSpace(rb.Target) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	certName := connector.RollbackObjectName(rb.Target+"-trstctl", rb.PredecessorFingerprint)
	// Confirm the object exists before re-binding. A LoadMaster that accepts a
	// bind naming a missing certificate would leave the service in a state
	// nobody chose, behind a receipt claiming the rollback worked.
	if err := c.mustExist(ctx, sb, "/access/certificates/"+url.PathEscape(certName)); err != nil {
		return fmt.Errorf("kemp: predecessor certificate %q: %w", certName, err)
	}
	if err := c.bind(ctx, sb, rb.Target, certName); err != nil {
		return fmt.Errorf("kemp: re-bind virtual service %q to predecessor: %w", rb.Target, err)
	}
	return nil
}

// bind points a virtual service at a named certificate. Deploy and Rollback
// share it so the two cannot drift into binding differently.
func (c *Connector) bind(ctx context.Context, sb connector.Sandbox, target, certName string) error {
	return c.call(ctx, sb, http.MethodPatch,
		"/access/virtual-services/"+url.PathEscape(target)+"/certificate", bindReq{CertName: certName})
}

// mustExist distinguishes "there is nothing to roll back to" from "the
// appliance did not answer". Only the second is worth retrying.
func (c *Connector) mustExist(ctx context.Context, sb connector.Sandbox, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.token))
	resp, err := sb.Request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_ = secret.DrainBounded(resp.Body, 4<<10)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return connector.ErrNoPredecessorInstalled
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
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
