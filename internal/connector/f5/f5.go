// SPDX-License-Identifier: BUSL-1.1

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
	"io"
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
	// The object name carries the certificate's fingerprint (epic D4), so a
	// second deployment installs a SECOND crypto object rather than overwriting
	// the first. That is what leaves a predecessor on the appliance for
	// Rollback to bind back to; before this, every deploy destroyed the only
	// thing a rollback could have used.
	//
	// Idempotency is unchanged and comes for free: the same certificate hashes
	// to the same name, so a retried deploy installs over itself.
	base := connector.DeployedObjectName(c.name, dep.Fingerprint)
	certName := base + ".crt"
	keyName := base + ".key"

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
	if err := c.bindProfile(ctx, sb, base, certName, keyName); err != nil {
		return fmt.Errorf("f5: bind to profile %q: %w", c.profile, err)
	}
	return nil
}

// Rollback re-points the Client SSL profile at an already-installed
// predecessor (epic D4).
//
// Nothing is uploaded and no key moves. That is not a limitation of this
// implementation, it is the reason the operation exists at all: the control
// plane holds no subject key after B1, so the only rollback it can perform is
// one that needs nothing from it.
//
// The predecessor's presence is CHECKED before the bind. A PATCH naming a
// missing crypto object can be accepted by the appliance and leave the profile
// in a state nobody intended; worse, reporting success when the object is gone
// would tell an operator a bad certificate had stopped serving traffic when it
// had not.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	base := connector.RollbackObjectName(c.name, rb.PredecessorFingerprint)
	certName := base + ".crt"
	keyName := base + ".key"

	if err := c.mustExist(ctx, sb, "/mgmt/tm/sys/crypto/cert/"+url.PathEscape(certName)); err != nil {
		return fmt.Errorf("f5: predecessor certificate %q: %w", certName, err)
	}
	if err := c.mustExist(ctx, sb, "/mgmt/tm/sys/crypto/key/"+url.PathEscape(keyName)); err != nil {
		return fmt.Errorf("f5: predecessor key %q: %w", keyName, err)
	}
	if err := c.bindProfile(ctx, sb, base, certName, keyName); err != nil {
		return fmt.Errorf("f5: re-bind profile %q to predecessor: %w", c.profile, err)
	}
	return nil
}

// bindProfile points the Client SSL profile at a named cert/key pair. Deploy
// and Rollback share it so the two cannot drift into binding differently — a
// rollback that bound a profile in a subtly different shape than a deploy would
// be a second code path nobody exercises until an incident.
func (c *Connector) bindProfile(ctx context.Context, sb connector.Sandbox, chainName, certName, keyName string) error {
	return c.callJSON(ctx, sb, http.MethodPatch, "/mgmt/tm/ltm/profile/client-ssl/"+c.profile, map[string]any{
		"certKeyChain": []map[string]string{{"name": chainName, "cert": certName, "key": keyName}},
	})
}

// mustExist reports ErrNoPredecessorInstalled when the object is absent, and
// the transport error otherwise. The distinction matters to the operator: "there
// is nothing to roll back to" is final, and "the appliance did not answer" is
// worth retrying.
func (c *Connector) mustExist(ctx context.Context, sb connector.Sandbox, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.user != "" || len(c.pass) > 0 {
		req.Header.Set("Authorization", c.basicAuth())
	}
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

// Readback asks the BIG-IP what the Client SSL profile is bound to (epic E2).
//
// The question a deploy cannot answer about itself. Upload succeeds, the crypto
// object installs, and the virtual server keeps presenting the previous
// certificate because the profile patch went to a different profile than the one
// the VIP uses — every step reporting success, clients getting the old cert
// until it expires.
//
// The fingerprint comes out of the OBJECT NAME rather than from a certificate
// the device re-serves. iControl REST will not hand back the DER of an installed
// crypto object, but D4 already puts the fingerprint prefix in the name it
// installs under, so the name is the comparison key. That is a real constraint
// of the API and not a shortcut: a family whose names did not carry it would
// have to report an empty fingerprint and be classified unknown.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, target string) (connector.Installed, error) {
	profile := target
	if profile == "" {
		profile = c.profile
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/mgmt/tm/ltm/profile/client-ssl/"+url.PathEscape(profile), nil)
	if err != nil {
		return connector.Installed{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.basicAuth())

	resp, err := sb.Request(req)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("f5: read back profile %q: %w", profile, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// The profile itself is absent. Distinct from "present and bound to
		// something else": one is a configuration that does not exist, the other
		// is a binding that did not move.
		return connector.Installed{}, nil
	}
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Installed{}, fmt.Errorf("f5: read back profile %q: status %d (response body redacted)",
			profile, resp.StatusCode)
	}
	var body struct {
		CertKeyChain []struct {
			Cert string `json:"cert"`
		} `json:"certKeyChain"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return connector.Installed{}, fmt.Errorf("f5: decode profile %q: %w", profile, err)
	}
	if len(body.CertKeyChain) == 0 || body.CertKeyChain[0].Cert == "" {
		// A profile with no chain is a real state on a BIG-IP, and it is not
		// ours — reporting it as bound-to-nothing rather than as absent keeps
		// the two apart for the classifier.
		return connector.Installed{ObjectName: profile}, nil
	}
	object := body.CertKeyChain[0].Cert
	return connector.Installed{
		Fingerprint: connector.FingerprintFromObjectName(object),
		ObjectName:  object,
		Bound:       true,
	}, nil
}
