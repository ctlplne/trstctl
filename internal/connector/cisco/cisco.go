// Package cisco is the Cisco ASA / Identity Services Engine (ISE) deployment
// connector (S10.11), built from the connector SDK (S5.5). Both the ASA and ISE
// expose an HTTPS management API (the ISE ERS / ASA REST API) that imports an
// identity certificate together with its private key; this connector deploys a
// renewed credential by POSTing it to that import endpoint.
//
// Like the other appliance connectors (F5 BIG-IP, Citrix NetScaler), it routes
// every privileged operation through the capability-gated Sandbox (sb.Request),
// so it is conformance-tested and outbox-delivered (AN-6) like every other
// connector. Authentication is HTTP Basic over TLS: the management username and
// password are sent in the Authorization header and are never logged — error
// messages carry only the response body and status, never the credential. Least
// privilege is net.dial to the management host alone; no filesystem, no exec.
//
// Key material is carried as []byte and the PEM is treated as opaque (AN-8). The
// connector imports no crypto/* (AN-3): the Basic credential is encoded with
// encoding/base64, which is not a cryptographic primitive.
package cisco

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

// defaultName is the certificate name used when a Deployment carries no target.
const defaultName = "trstctl"

// importPath is the management API endpoint that imports an identity certificate
// and its private key (the ISE ERS / ASA REST certificate import).
const importPath = "/api/certificate/import"

// Connector deploys certificates to a Cisco ASA / ISE over its HTTPS management
// API (the ISE ERS / ASA REST API), authenticating with HTTP Basic.
//
// The management password is held as []byte, never a string, so it can be wiped
// and is not freely copied by the GC (AN-8). Close zeroizes it.
type Connector struct {
	baseURL string // management base, e.g. https://ise.example (no trailing slash)
	host    string // host[:port] of baseURL, for the net.dial grant
	user    string
	pass    []byte // management password (AN-8: []byte, wiped by Close)
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// New returns a Cisco connector for the management API at baseURL, authenticating
// with the given username and password over HTTP Basic. The grant's net.dial host
// is derived from baseURL so the sandbox admits exactly the management endpoint.
//
// password is taken as []byte (AN-8). The connector copies it into its own buffer
// so the caller may wipe theirs; call Close to zeroize the connector's copy.
func New(baseURL, username string, password []byte, opts ...Option) *Connector {
	c := &Connector{
		baseURL: strings.TrimRight(baseURL, "/"),
		user:    username,
		pass:    append([]byte(nil), password...),
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close zeroizes the held management password (AN-8).
func (c *Connector) Close() {
	secret.Wipe(c.pass)
	c.pass = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "cisco" }

// Capabilities declares the least privilege the connector needs: reach the
// management host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy imports the renewed certificate and key under the certificate name
// given by dep.Target (defaulting to "trstctl"). It POSTs the credential to the
// management API's import endpoint with HTTP Basic auth; a 2xx is success, a
// non-2xx fails with the response body — never the password.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name := dep.Target
	if name == "" {
		name = defaultName
	}

	body, err := json.Marshal(importRequest{
		Name:        name,
		Certificate: string(dep.CertPEM),
		PrivateKey:  string(dep.KeyPEM),
	})
	if err != nil {
		return fmt.Errorf("cisco: encode request: %w", err)
	}
	// The marshaled body carries the private-key PEM on the wire. It is the
	// transient edge copy (the long-lived key stays []byte in dep.KeyPEM); wipe it
	// once the request has been sent so the key does not linger in this buffer (AN-8).
	defer secret.Wipe(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+importPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.basicAuth())

	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("cisco: import certificate %q: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return fmt.Errorf("cisco: import certificate %q: status %d: read response: %w", name, resp.StatusCode, err)
		}
		return fmt.Errorf("cisco: import certificate %q: status %d: %s", name, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// basicAuth builds the HTTP Basic Authorization header value,
// "Basic base64(user:pass)", using encoding/base64 (not a crypto primitive, so
// AN-3 is preserved). The credential never appears in a log or an error. The
// "user:pass" form is assembled in a []byte that is wiped after encoding so the
// password is not left in a GC-managed string (AN-8).
func (c *Connector) basicAuth() string {
	raw := make([]byte, 0, len(c.user)+1+len(c.pass))
	raw = append(raw, c.user...)
	raw = append(raw, ':')
	raw = append(raw, c.pass...)
	enc := "Basic " + base64.StdEncoding.EncodeToString(raw)
	secret.Wipe(raw) // the cleartext user:pass copy does not outlive this call
	return enc
}

// importRequest is the certificate-import body for the Cisco management API. The
// certificate and key are carried as PEM strings on the wire; trstctl holds the
// material as []byte (AN-8) until this final marshal.
type importRequest struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}
