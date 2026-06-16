// Package netscaler is the Citrix ADC (NetScaler) deployment connector (S5.13.1),
// built from the connector SDK (S5.5). A NetScaler is an appliance driven over
// the NITRO REST API, so — like the F5 BIG-IP connector — it routes through the
// capability-gated Sandbox (sb.Request) and is conformance-tested and
// outbox-delivered.
//
// Renewal is the full end-to-end flow: open a NITRO session (login), upload the
// renewed certificate and key as system files under /nsconfig/ssl, update the
// existing SSL certkey to point at them (which reloads the certificate so it goes
// live), and close the session (logout, best-effort). Authentication is the
// NITRO session-token model: credentials cross the wire once at login, and a
// short-lived NITRO_AUTH_TOKEN cookie authorizes the rest — so this connector
// imports no crypto/* (AN-3). Least privilege is net.dial to the NSIP host alone;
// no filesystem, no exec. Key material is carried as []byte (AN-8) and the PEM is
// opaque.
package netscaler

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

const defaultFileLocation = "/nsconfig/ssl"

// Connector deploys certificates to a Citrix ADC (NetScaler) over NITRO.
//
// The NITRO password is held as []byte, never a string, so it can be wiped and is
// not freely copied by the GC (AN-8). Close zeroizes it.
type Connector struct {
	baseURL      string // NSIP management base, e.g. https://ns.example (no trailing slash)
	host         string // host of baseURL, for the net.dial grant
	user         string
	pass         []byte // NITRO password (AN-8: []byte, wiped by Close)
	fileLocation string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithFileLocation overrides where cert/key files are uploaded (default
// /nsconfig/ssl).
func WithFileLocation(path string) Option {
	return func(c *Connector) {
		if path != "" {
			c.fileLocation = path
		}
	}
}

// New returns a NetScaler connector for the appliance at baseURL, authenticating
// with the NITRO credentials.
//
// pass is taken as []byte (AN-8). The connector copies it into its own buffer so
// the caller may wipe theirs; call Close to zeroize the connector's copy.
func New(baseURL, user string, pass []byte, opts ...Option) *Connector {
	c := &Connector{
		baseURL:      strings.TrimRight(baseURL, "/"),
		user:         user,
		pass:         append([]byte(nil), pass...),
		fileLocation: defaultFileLocation,
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close zeroizes the held NITRO password (AN-8).
func (c *Connector) Close() {
	secret.Wipe(c.pass)
	c.pass = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "netscaler" }

// Capabilities declares the least privilege the connector needs: reach the NSIP
// host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy uploads the renewed cert and key and rebinds the SSL certkey named by
// dep.Target to them.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("netscaler: %w", err)
	}
	defer func() { _ = c.logout(ctx, sb, token) }()

	certFile := dep.Target + ".crt"
	keyFile := dep.Target + ".key"
	if err := c.upload(ctx, sb, token, certFile, dep.CertPEM); err != nil {
		return fmt.Errorf("netscaler: upload certificate: %w", err)
	}
	if err := c.upload(ctx, sb, token, keyFile, dep.KeyPEM); err != nil {
		return fmt.Errorf("netscaler: upload key: %w", err)
	}
	if err := c.rebind(ctx, sb, token, dep.Target, certFile, keyFile); err != nil {
		return fmt.Errorf("netscaler: rebind certkey %q: %w", dep.Target, err)
	}
	return nil
}

func (c *Connector) login(ctx context.Context, sb connector.Sandbox) (string, error) {
	// The NITRO login body carries the password once on the wire; string(c.pass)
	// is the transient edge form of the []byte secret (AN-8). The marshaled body
	// inside call() is short-lived and not retained.
	data, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/login", "", loginReq{
		Login: credentials{Username: c.user, Password: string(c.pass)},
	})
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	var lr struct {
		SessionID string `json:"sessionid"`
	}
	_ = json.Unmarshal(data, &lr)
	return lr.SessionID, nil
}

func (c *Connector) upload(ctx context.Context, sb connector.Sandbox, token, filename string, content []byte) error {
	_, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/systemfile", token, systemfileReq{
		Systemfile: systemfile{
			Filename:     filename,
			Filecontent:  base64.StdEncoding.EncodeToString(content),
			Filelocation: c.fileLocation,
			Fileencoding: "BASE64",
		},
	})
	return err
}

func (c *Connector) rebind(ctx context.Context, sb connector.Sandbox, token, certkey, certFile, keyFile string) error {
	_, err := c.call(ctx, sb, http.MethodPut, "/nitro/v1/config/sslcertkey", token, sslcertkeyReq{
		Sslcertkey: sslcertkey{Certkey: certkey, Cert: certFile, Key: keyFile, NoDomainCheck: true},
	})
	return err
}

// logout closes the NITRO session. It is best-effort: the certificate is already
// deployed, so a failed logout must not fail the deployment.
func (c *Connector) logout(ctx context.Context, sb connector.Sandbox, token string) error {
	if token == "" {
		return nil
	}
	_, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/logout", token, logoutReq{})
	return err
}

// call performs a NITRO request through the sandbox, attaching the session token
// (when present) as the NITRO_AUTH_TOKEN cookie, and returns the response body.
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
		req.AddCookie(&http.Cookie{Name: "NITRO_AUTH_TOKEN", Value: token})
	}

	resp, err := sb.Request(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

type loginReq struct {
	Login credentials `json:"login"`
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type logoutReq struct {
	Logout struct{} `json:"logout"`
}

type systemfileReq struct {
	Systemfile systemfile `json:"systemfile"`
}

type systemfile struct {
	Filename     string `json:"filename"`
	Filecontent  string `json:"filecontent"`
	Filelocation string `json:"filelocation"`
	Fileencoding string `json:"fileencoding"`
}

type sslcertkeyReq struct {
	Sslcertkey sslcertkey `json:"sslcertkey"`
}

type sslcertkey struct {
	Certkey       string `json:"certkey"`
	Cert          string `json:"cert"`
	Key           string `json:"key"`
	NoDomainCheck bool   `json:"nodomaincheck"`
}
