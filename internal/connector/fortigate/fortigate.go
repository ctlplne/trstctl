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

	"trustctl.io/trustctl/internal/connector"
	"trustctl.io/trustctl/internal/pluginhost"
)

// defaultName is the local-certificate object name used when the deployment
// target does not name one.
const defaultName = "trustctl"

// Connector deploys certificates to a Fortinet FortiGate / FortiWeb appliance
// over the FortiOS REST API.
type Connector struct {
	baseURL string // FortiOS management base, e.g. https://fgt.example (no trailing slash)
	host    string // host of baseURL, for the net.dial grant
	token   string // FortiOS REST API token (AN-8-adjacent: never logged)
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector. (None are required today — baseURL is the
// endpoint and the host is derived from it — but the variadic keeps the
// constructor forward-compatible with the other connectors.)
type Option func(*Connector)

// New returns a FortiGate/FortiWeb connector for the appliance at baseURL,
// authenticating with the FortiOS REST API token. baseURL is the endpoint; the
// net.dial grant host is derived from it.
func New(baseURL, token string, opts ...Option) *Connector {
	c := &Connector{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
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
// vpn.certificate/local object named by dep.Target (default "trustctl"). PUT is
// an upsert, so a redeploy of the same credential is idempotent: it overwrites
// the object in place with identical material.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name := certName(dep.Target)

	body, err := json.Marshal(localCert{
		Name:        name,
		Certificate: string(dep.CertPEM),
		PrivateKey:  string(dep.KeyPEM),
	})
	if err != nil {
		return fmt.Errorf("fortigate: encode request: %w", err)
	}

	endpoint := c.baseURL + "/api/v2/cmdb/vpn.certificate/local/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// FortiOS REST API token, presented as a bearer credential. Never logged.
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("fortigate: deploy certificate %q: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		// The response body may echo the request; FortiOS does not echo the
		// Authorization header, and we never add the token to the error. Bound
		// the read so a hostile/large body cannot blow up memory.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fortigate: deploy certificate %q: status %d: %s",
			name, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
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
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private-key"`
}
