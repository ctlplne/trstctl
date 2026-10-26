// SPDX-License-Identifier: BUSL-1.1

// Package a10 is the A10 Thunder/AX load-balancer deployment connector.
// It drives the appliance over an aXAPI-style HTTPS management API: authenticate,
// upload renewed certificate/key files, then bind the client-SSL template. The
// connector has only net.dial capability for the management host; no filesystem
// or process execution.
package a10

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
	defer secret.Wipe(token)
	// D4: file names carry the certificate's fingerprint so a second deploy
	// leaves the first in place. The client-ssl TEMPLATE name is unchanged —
	// virtual ports reference it, and renaming it would break bindings an
	// operator already has.
	base := connector.DeployedObjectName(dep.Target, dep.Fingerprint)
	certFile := base + ".crt"
	keyFile := base + ".key"
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

// Rollback re-points a client-SSL template at the predecessor's already
// uploaded files (epic D4). Nothing is uploaded; the template keeps its name so
// every virtual port bound to it is unaffected.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" || strings.TrimSpace(rb.Target) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)

	base := connector.RollbackObjectName(rb.Target, rb.PredecessorFingerprint)
	certFile := base + ".crt"
	keyFile := base + ".key"
	if err := c.mustExistFile(ctx, sb, token, "ssl-cert", certFile); err != nil {
		return fmt.Errorf("a10: predecessor certificate %q: %w", certFile, err)
	}
	if object := strings.TrimSpace(rb.PredecessorKeyObject); object != "" {
		// A122: the A10 generated this key into a job-named file. Its CSR
		// beside it proves the key was made here; the key itself is not read.
		if _, found, err := c.readCSR(ctx, sb, token, object+".csr"); err != nil {
			return fmt.Errorf("a10: predecessor appliance key %q: %w", object, err)
		} else if !found {
			return fmt.Errorf("a10: predecessor appliance key %q: %w", object, connector.ErrNoPredecessorInstalled)
		}
		if err := c.bind(ctx, sb, token, rb.Target, certFile, object+".key"); err != nil {
			return fmt.Errorf("a10: re-bind client-ssl template %q to the predecessor and its appliance key: %w", rb.Target, err)
		}
		return nil
	}
	// The key too: the template binds both, the deploy uploads them separately,
	// and binding a template to a key that is not present takes the virtual port
	// down instead of restoring it.
	if err := c.mustExistFile(ctx, sb, token, "ssl-key", keyFile); err != nil {
		return fmt.Errorf("a10: predecessor key %q: %w", keyFile, err)
	}
	if err := c.bind(ctx, sb, token, rb.Target, certFile, keyFile); err != nil {
		return fmt.Errorf("a10: re-bind client-ssl template %q to predecessor: %w", rb.Target, err)
	}
	return nil
}

// Readback asks the A10 which certificate file the client-SSL template names
// (epic E2). The template is what virtual ports reference and keeps its name
// across deploys; the certificate file a deploy points it at carries the
// fingerprint prefix, so the file name is the comparison key.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, target string) (connector.Installed, error) {
	token, err := c.login(ctx, sb)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)
	data, err := c.call(ctx, sb, http.MethodGet, "/axapi/v3/slb/template/client-ssl/"+url.PathEscape(target), token, nil)
	defer secret.Wipe(data)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return connector.Installed{}, nil
		}
		return connector.Installed{}, fmt.Errorf("a10: read back client-ssl template %q: %w", target, err)
	}
	var body struct {
		ClientSSL struct {
			Cert string `json:"cert"`
		} `json:"client-ssl"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return connector.Installed{}, fmt.Errorf("a10: decode client-ssl template %q (details redacted)", target)
	}
	if body.ClientSSL.Cert == "" {
		return connector.Installed{ObjectName: target}, nil
	}
	return connector.Installed{
		Fingerprint: connector.FingerprintFromObjectName(body.ClientSSL.Cert),
		ObjectName:  body.ClientSSL.Cert,
		Bound:       true,
	}, nil
}

// mustExistFile reports ErrNoPredecessorInstalled when the uploaded file is
// absent. Binding a template to a file that is not there would take the virtual
// port down rather than restore it — the opposite of what a rollback is for.
func (c *Connector) mustExistFile(ctx context.Context, sb connector.Sandbox, token []byte, kind, filename string) error {
	data, err := c.call(ctx, sb, http.MethodGet,
		"/axapi/v3/file/"+kind+"/"+url.PathEscape(filename), token, nil)
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
	data, err := c.call(ctx, sb, http.MethodPost, "/axapi/v3/auth", nil, authRequest{
		Credentials: credentials{Username: c.user, Password: secretjson.StringBytes(c.pass)},
	})
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	defer secret.Wipe(data)
	var out struct {
		AuthResponse struct {
			Signature secretjson.StringBytes `json:"signature"`
		} `json:"authresponse"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("login: decode response failed (details redacted)")
	}
	defer secret.Wipe(out.AuthResponse.Signature)
	if len(bytes.TrimSpace(out.AuthResponse.Signature)) == 0 {
		return nil, fmt.Errorf("login: response missing authresponse.signature")
	}
	return append([]byte(nil), out.AuthResponse.Signature...), nil
}

func (c *Connector) upload(ctx context.Context, sb connector.Sandbox, token []byte, kind, filename string, content []byte) error {
	data, err := c.call(ctx, sb, http.MethodPost, "/axapi/v3/file/"+kind, token, map[string]any{
		kind: struct {
			File        string                 `json:"file"`
			FileContent secretjson.Base64Bytes `json:"file-content"`
		}{
			File:        filename,
			FileContent: secretjson.Base64Bytes(content),
		},
	})
	secret.Wipe(data)
	return err
}

func (c *Connector) bind(ctx context.Context, sb connector.Sandbox, token []byte, template, certFile, keyFile string) error {
	data, err := c.call(ctx, sb, http.MethodPut, "/axapi/v3/slb/template/client-ssl/"+url.PathEscape(template), token, map[string]any{
		"client-ssl": map[string]string{"name": template, "cert": certFile, "key": keyFile},
	})
	secret.Wipe(data)
	return err
}

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
		req.Header.Set("Authorization", secrettext.Prefixed("A10 ", token))
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

type authRequest struct {
	Credentials credentials `json:"credentials"`
}

type credentials struct {
	Username string                 `json:"username"`
	Password secretjson.StringBytes `json:"password"`
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

// Takedown deletes the fingerprint-named ssl-cert and ssl-key files a deploy
// uploaded (A43). The aXAPI refuses to delete a file a client-ssl template
// still references; that refusal is reported as ErrTakedownObjectBound.
func (c *Connector) Takedown(ctx context.Context, sb connector.Sandbox, td connector.Takedown) error {
	if strings.TrimSpace(td.Fingerprint) == "" || strings.TrimSpace(td.Target) == "" {
		return connector.ErrTakedownNotInstalled
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)

	base := connector.RollbackObjectName(td.Target, td.Fingerprint)
	found := false
	for _, file := range []struct{ kind, name string }{{"ssl-key", base + ".key"}, {"ssl-cert", base + ".crt"}} {
		data, err := c.call(ctx, sb, http.MethodDelete,
			"/axapi/v3/file/"+file.kind+"/"+url.PathEscape(file.name), token, nil)
		secret.Wipe(data)
		var se *statusError
		switch {
		case err == nil:
			found = true
		case errors.As(err, &se) && se.code == http.StatusNotFound:
		case errors.As(err, &se) && se.code == http.StatusConflict:
			return connector.ErrTakedownObjectBound
		default:
			return fmt.Errorf("a10: remove %s %q: %w", file.kind, file.name, err)
		}
	}
	if !found {
		return connector.ErrTakedownNotInstalled
	}
	return nil
}

// RollbackLegacy re-points the client-ssl template at the files a
// pre-fingerprint deploy uploaded under the target-derived name (A45).
func (c *Connector) RollbackLegacy(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if strings.TrimSpace(rb.Target) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	token, err := c.login(ctx, sb)
	if err != nil {
		return fmt.Errorf("a10: %w", err)
	}
	defer secret.Wipe(token)
	base := connector.LegacyObjectName(rb.Target)
	certFile := base + ".crt"
	keyFile := base + ".key"
	if err := c.mustExistFile(ctx, sb, token, "ssl-cert", certFile); err != nil {
		return fmt.Errorf("a10: legacy certificate %q: %w", certFile, err)
	}
	if err := c.mustExistFile(ctx, sb, token, "ssl-key", keyFile); err != nil {
		return fmt.Errorf("a10: legacy key %q: %w", keyFile, err)
	}
	if err := c.bind(ctx, sb, token, rb.Target, certFile, keyFile); err != nil {
		return fmt.Errorf("a10: re-bind client-ssl template %q to legacy files: %w", rb.Target, err)
	}
	return nil
}
