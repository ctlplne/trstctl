// SPDX-License-Identifier: BUSL-1.1

// Package fortigate is the Fortinet FortiGate / FortiWeb deployment connector
// (S10.9), built from the connector SDK (S5.5). A FortiGate (and the FortiWeb
// web-application firewall, which shares the same FortiOS REST surface for
// local certificates) is driven over the FortiOS REST API, so — like the F5
// BIG-IP, Citrix ADC, and AWS ACM connectors — it routes every privileged
// operation through the capability-gated Sandbox (sb.Request) and is
// conformance-tested and outbox-delivered.
//
// Renewal is a single in-place upsert: PUT the renewed certificate and key to
// the named vpn.certificate/local object on the appliance, which replaces the
// material and reloads it so it goes live. Authentication is the FortiOS REST
// API token, presented as an HTTP bearer credential — it crosses the wire on
// every call and is never logged, never placed in an error, and is carried in a
// field, not in the deployment payload. So this connector imports no crypto/*
// (AN-3): the token is opaque and there is no signing. Least privilege is
// net.dial to the appliance host alone; no filesystem, no exec. Key material is
// carried as []byte (AN-8) and the PEM is opaque (no certificate parse).
package fortigate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

// defaultName is the local-certificate object name used when the deployment
// target does not name one.
const defaultName = "trstctl"

// BindTo names the FortiOS setting a deploy points at the uploaded
// certificate (A44). With a binding, deploys upload under a fingerprint-named
// local certificate and move only the setting, so the predecessor object
// survives and a rollback is one setting change back to it.
type BindTo string

const (
	// BindAdmin binds system.global admin-server-cert (the GUI/API listener).
	BindAdmin BindTo = "admin"
	// BindSSLVPN binds vpn.ssl.settings servercert (the SSL-VPN portal).
	BindSSLVPN BindTo = "ssl-vpn"
)

const (
	adminSettingPath  = "/api/v2/cmdb/system/global"
	sslVPNSettingPath = "/api/v2/cmdb/vpn.ssl/settings"
	localCertPath     = "/api/v2/cmdb/vpn.certificate/local/"
)

// ParseBindTo validates an operator-supplied bind_to value.
func ParseBindTo(value string) (BindTo, error) {
	switch BindTo(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case BindAdmin:
		return BindAdmin, nil
	case BindSSLVPN:
		return BindSSLVPN, nil
	default:
		return "", fmt.Errorf("fortigate: bind_to must be %q or %q", BindAdmin, BindSSLVPN)
	}
}

func (b BindTo) settingPath() string {
	if b == BindSSLVPN {
		return sslVPNSettingPath
	}
	return adminSettingPath
}

func (b BindTo) settingField() string {
	if b == BindSSLVPN {
		return "servercert"
	}
	return "admin-server-cert"
}

// Connector deploys certificates to a Fortinet FortiGate / FortiWeb appliance
// over the FortiOS REST API.
//
// The FortiOS REST API token is a bearer credential; it is held as []byte, never
// a string, so it can be wiped and is not freely copied by the GC (AN-8). Close
// zeroizes it.
type Connector struct {
	baseURL string // FortiOS management base, e.g. https://fgt.example (no trailing slash)
	host    string // host of baseURL, for the net.dial grant
	token   []byte // FortiOS REST API token (AN-8: []byte, never logged, wiped by Close)
	bindTo  BindTo // empty keeps the legacy in-place deploy under the target name
}

// WithBindTo makes deploys fingerprint-named and bound to the given setting,
// which is what makes the target rollback-capable.
func WithBindTo(bind BindTo) Option { return func(c *Connector) { c.bindTo = bind } }

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector. (None are required today — baseURL is the
// endpoint and the host is derived from it — but the variadic keeps the
// constructor forward-compatible with the other connectors.)
type Option func(*Connector)

// New returns a FortiGate/FortiWeb connector for the appliance at baseURL,
// authenticating with the FortiOS REST API token. baseURL is the endpoint; the
// net.dial grant host is derived from it.
//
// token is taken as []byte (AN-8). The connector copies it into its own buffer so
// the caller may wipe theirs; call Close to zeroize the connector's copy.
func New(baseURL string, token []byte, opts ...Option) *Connector {
	c := &Connector{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   append([]byte(nil), token...),
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close zeroizes the held FortiOS API token (AN-8).
func (c *Connector) Close() {
	secret.Wipe(c.token)
	c.token = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "fortigate" }

// Capabilities declares the least privilege the connector needs: reach the
// appliance host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy upserts the renewed certificate and key into the FortiOS
// vpn.certificate/local object named by dep.Target (default "trstctl"). PUT is
// an upsert, so a redeploy of the same credential is idempotent: it overwrites
// the object in place with identical material.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name := certName(dep.Target)
	if c.bindTo != "" {
		// Fingerprint-named so the predecessor survives (A44). FortiOS caps a
		// local certificate name at 35 characters; the target base must leave
		// room for the 13-character fingerprint suffix.
		name = connector.DeployedObjectName(name, dep.Fingerprint)
		if len(name) > 35 {
			return fmt.Errorf("fortigate: object name %q exceeds the 35-character FortiOS limit; shorten the target name", name)
		}
	}

	body, err := json.Marshal(localCert{
		Name:        name,
		Certificate: secretjson.StringBytes(dep.CertPEM),
		PrivateKey:  secretjson.StringBytes(dep.KeyPEM),
	})
	if err != nil {
		return fmt.Errorf("fortigate: encode request: %w", err)
	}
	// The marshaled body carries the private-key PEM on the wire; it is the
	// transient edge copy (the long-lived key stays []byte in dep.KeyPEM). Wipe it
	// after the request so the key does not linger in this buffer (AN-8).
	defer secret.Wipe(body)
	if err := c.call(ctx, sb, http.MethodPut, localCertPath+url.PathEscape(name), body); err != nil {
		return fmt.Errorf("fortigate: deploy certificate %q: %w", name, err)
	}
	if c.bindTo == "" {
		return nil
	}
	if err := c.bind(ctx, sb, name); err != nil {
		return fmt.Errorf("fortigate: bind %s to %q: %w", c.bindTo.settingField(), name, err)
	}
	return nil
}

// Rollback re-points the configured setting at the predecessor's
// fingerprint-named object, which must still be on the appliance (A44).
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if c.bindTo == "" {
		return connector.ErrRollbackNotConfigured
	}
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	name := connector.RollbackObjectName(certName(rb.Target), rb.PredecessorFingerprint)
	if err := c.mustExist(ctx, sb, localCertPath+url.PathEscape(name)); err != nil {
		return fmt.Errorf("fortigate: predecessor certificate %q: %w", name, err)
	}
	if err := c.bind(ctx, sb, name); err != nil {
		return fmt.Errorf("fortigate: re-bind %s to predecessor %q: %w", c.bindTo.settingField(), name, err)
	}
	return nil
}

// Readback reports the local certificate the configured setting points at
// (A44). It asks the device, not the deploy: an operator who re-pointed the
// setting by hand is reported as diverged, not as clean.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, _ string) (connector.Installed, error) {
	if c.bindTo == "" {
		return connector.Installed{}, connector.ErrReadbackNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+c.bindTo.settingPath(), nil)
	if err != nil {
		return connector.Installed{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.token))
	resp, err := sb.Request(req)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("fortigate: read back %s: %w", c.bindTo.settingField(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Installed{}, fmt.Errorf("fortigate: read back %s: status %d (response body redacted)", c.bindTo.settingField(), resp.StatusCode)
	}
	var body struct {
		Results map[string]any `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return connector.Installed{}, fmt.Errorf("fortigate: decode %s: %w", c.bindTo.settingField(), err)
	}
	name, _ := body.Results[c.bindTo.settingField()].(string)
	if strings.TrimSpace(name) == "" {
		return connector.Installed{ObjectName: c.bindTo.settingField()}, nil
	}
	return connector.Installed{Fingerprint: connector.FingerprintFromObjectName(name), ObjectName: name, Bound: true}, nil
}

func (c *Connector) bind(ctx context.Context, sb connector.Sandbox, name string) error {
	body, err := json.Marshal(map[string]string{c.bindTo.settingField(): name})
	if err != nil {
		return err
	}
	return c.call(ctx, sb, http.MethodPut, c.bindTo.settingPath(), body)
}

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

// call performs one FortiOS REST request with the bearer token. The token
// header value is the transient edge form of the []byte token; never logged.
func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, path string, body []byte) error {
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

// certName derives the local-certificate object name from the deployment
// target, falling back to the default when the target is empty.
func certName(target string) string {
	if target == "" {
		return defaultName
	}
	return target
}

// localCert is the FortiOS vpn.certificate/local object body. certificate and
// private-key are PEM strings (the FortiOS schema field names).
type localCert struct {
	Name        string                 `json:"name"`
	Certificate secretjson.StringBytes `json:"certificate"`
	PrivateKey  secretjson.StringBytes `json:"private-key"`
}
