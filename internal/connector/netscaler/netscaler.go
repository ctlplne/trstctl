// SPDX-License-Identifier: MPL-2.0

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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
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
	defer secret.Wipe(token)
	defer func() { _ = c.logout(ctx, sb, token) }()

	// D4: the uploaded FILE names carry the certificate's fingerprint, so a
	// second deployment does not overwrite the first. The sslcertkey object
	// name stays dep.Target — that is what vservers are bound to, and changing
	// it would break every binding an operator already has. Rollback re-points
	// the same certkey at the predecessor's files.
	base := connector.DeployedObjectName(dep.Target, dep.Fingerprint)
	certFile := base + ".crt"
	keyFile := base + ".key"
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

// Rollback re-points an existing sslcertkey at the predecessor's already
// uploaded files (epic D4).
//
// Nothing is uploaded. The certkey object keeps its name, so every vserver
// bound to it is unaffected — what changes is which file pair it resolves to,
// which is exactly the state a deploy changed and the only thing that needs
// undoing.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" || strings.TrimSpace(rb.Target) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("netscaler: %w", err)
	}
	defer secret.Wipe(token)
	defer func() { _ = c.logout(ctx, sb, token) }()

	base := connector.RollbackObjectName(rb.Target, rb.PredecessorFingerprint)
	certFile := base + ".crt"
	keyFile := base + ".key"
	// Confirm the predecessor file is still on the appliance. A NITRO PUT that
	// names a missing file can be accepted and leave the certkey unusable —
	// which would take the listener down instead of restoring it.
	if err := c.mustExistFile(ctx, sb, token, certFile); err != nil {
		return fmt.Errorf("netscaler: predecessor file %q: %w", certFile, err)
	}
	// BOTH halves. The certkey is bound to a cert AND a key, and the deploy
	// uploads them in two separate calls — so a deploy that failed between them
	// leaves an orphan .crt with no matching .key. Checking only the certificate
	// would then bind the certkey to a key that is not there, which by this
	// connector's own account leaves the listener down: the rollback would take
	// the service off the air rather than restore it, and report success.
	if err := c.mustExistFile(ctx, sb, token, keyFile); err != nil {
		return fmt.Errorf("netscaler: predecessor key file %q: %w", keyFile, err)
	}
	if err := c.rebind(ctx, sb, token, rb.Target, certFile, keyFile); err != nil {
		return fmt.Errorf("netscaler: re-bind certkey %q to predecessor: %w", rb.Target, err)
	}
	return nil
}

// mustExistFile reports ErrNoPredecessorInstalled when the system file is
// absent, and the transport error otherwise.
func (c *Connector) mustExistFile(ctx context.Context, sb connector.Sandbox, token []byte, filename string) error {
	// PathEscape, not QueryEscape: NITRO's args= is a comma-separated key:value
	// list, not a form body, so QueryEscape's space-to-'+' substitution corrupts
	// any target name containing a space — and the target name is free-form
	// operator text. PathEscape leaves ':' and ',' literal, so the args syntax
	// still parses.
	path := "/nitro/v1/config/systemfile?args=filename:" + url.PathEscape(filename) +
		",filelocation:" + url.PathEscape(c.fileLocation)
	data, err := c.call(ctx, sb, http.MethodGet, path, token, nil)
	secret.Wipe(data)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return connector.ErrNoPredecessorInstalled
		}
		// Anything else — a transport failure, an auth failure, a 500 — is NOT
		// "there is nothing to roll back to". It is worth retrying, and telling
		// an operator otherwise sends them to reissue a certificate when the
		// appliance was simply unreachable.
		return err
	}
	return nil
}

func (c *Connector) login(ctx context.Context, sb connector.Sandbox) ([]byte, error) {
	data, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/login", nil, loginReq{
		Login: credentials{Username: c.user, Password: secretjson.StringBytes(c.pass)},
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	defer secret.Wipe(data)
	var lr struct {
		SessionID secretjson.StringBytes `json:"sessionid"`
		ErrorCode int                    `json:"errorcode"`
	}
	if err := json.Unmarshal(data, &lr); err != nil {
		return nil, fmt.Errorf("login: decode response failed (details redacted)")
	}
	defer secret.Wipe(lr.SessionID)
	if lr.ErrorCode != 0 {
		return nil, fmt.Errorf("login: NITRO error %d (response message redacted)", lr.ErrorCode)
	}
	if len(bytes.TrimSpace(lr.SessionID)) == 0 {
		return nil, fmt.Errorf("login: response missing sessionid")
	}
	return append([]byte(nil), lr.SessionID...), nil
}

func (c *Connector) upload(ctx context.Context, sb connector.Sandbox, token []byte, filename string, content []byte) error {
	data, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/systemfile", token, systemfileReq{
		Systemfile: systemfile{
			Filename:     filename,
			Filecontent:  secretjson.Base64Bytes(content),
			Filelocation: c.fileLocation,
			Fileencoding: "BASE64",
		},
	})
	secret.Wipe(data)
	return err
}

func (c *Connector) rebind(ctx context.Context, sb connector.Sandbox, token []byte, certkey, certFile, keyFile string) error {
	data, err := c.call(ctx, sb, http.MethodPut, "/nitro/v1/config/sslcertkey", token, sslcertkeyReq{
		Sslcertkey: sslcertkey{Certkey: certkey, Cert: certFile, Key: keyFile, NoDomainCheck: true},
	})
	secret.Wipe(data)
	return err
}

// logout closes the NITRO session. It is best-effort: the certificate is already
// deployed, so a failed logout must not fail the deployment.
func (c *Connector) logout(ctx context.Context, sb connector.Sandbox, token []byte) error {
	if len(token) == 0 {
		return nil
	}
	data, err := c.call(ctx, sb, http.MethodPost, "/nitro/v1/config/logout", token, logoutReq{})
	secret.Wipe(data)
	return err
}

// call performs a NITRO request through the sandbox, attaching the session token
// (when present) as the NITRO_AUTH_TOKEN cookie, and returns the response body.
func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, path string, token []byte, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		req.AddCookie(&http.Cookie{Name: "NITRO_AUTH_TOKEN", Value: secrettext.String(token)}) // #nosec G124 -- cookie on an outbound API request; response-cookie attributes do not apply (CWE-1004)
	}

	resp, err := sb.Request(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, &statusError{code: resp.StatusCode}
	}
	data, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read response (details redacted)")
	}
	return data, nil
}

type loginReq struct {
	Login credentials `json:"login"`
}

type credentials struct {
	Username string                 `json:"username"`
	Password secretjson.StringBytes `json:"password"`
}

type logoutReq struct {
	Logout struct{} `json:"logout"`
}

type systemfileReq struct {
	Systemfile systemfile `json:"systemfile"`
}

type systemfile struct {
	Filename     string                 `json:"filename"`
	Filecontent  secretjson.Base64Bytes `json:"filecontent"`
	Filelocation string                 `json:"filelocation"`
	Fileencoding string                 `json:"fileencoding"`
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

// statusError carries the HTTP status a call failed with, so a caller can
// classify on the CODE rather than on the text of a message.
//
// It exists because the text form is genuinely dangerous here. A transport
// failure's error carries the request URL, and the URL now contains a
// fingerprint-derived object name (epic D4) — so a "connection refused" against
// an object whose 12 hex characters happen to contain "404" would match a
// substring test and be reported as the definitive, non-retryable "the
// predecessor is no longer installed." Roughly one fingerprint in four hundred.
// The operator would be told to reissue when the appliance was merely
// unreachable.
type statusError struct{ code int }

func (e *statusError) Error() string {
	return fmt.Sprintf("status %d (response body redacted)", e.code)
}
