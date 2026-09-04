// SPDX-License-Identifier: MPL-2.0

// Package azurekv is the Azure Key Vault deployment connector (S5.12), built from
// the connector SDK (S5.5). A renewed credential is deployed by importing it into
// a named vault certificate (PUT /certificates/{name}/import), which creates a
// new version of that certificate — the in-place renewal path.
//
// Like the AWS ACM connector (S5.11), and unlike the Key Vault *issuance* plugin
// (internal/ca/azurekv) which models the operation behind a pure-Go seam and
// leaves AAD auth to the Azure SDK, a deployment connector must route every
// privileged operation through the capability-gated Sandbox so it is
// conformance-tested and outbox-delivered. So it speaks the Key Vault REST API
// directly — an HTTPS PUT through sb.Request — authenticated with an Entra ID
// (AAD) bearer token from a TokenProvider seam (StaticToken, or the
// ClientCredentials provider in token.go). Bearer auth needs no request signing,
// so this connector imports no crypto/* at all (AN-3).
//
// The credential is imported as a PEM bundle (private key followed by the
// certificate chain), carried as []byte (AN-8); the package treats the PEM as
// opaque.
package azurekv

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
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultAPIVersion = "7.4"
	pemContentType    = "application/x-pem-file"
)

// Connector imports renewed certificates into Azure Key Vault.
type Connector struct {
	vaultURL   string // base URL, e.g. https://myvault.vault.azure.net (no trailing slash)
	host       string // host of vaultURL, for the net.dial grant
	tokens     TokenProvider
	apiVersion string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithAPIVersion overrides the Key Vault REST API version (default 7.4).
func WithAPIVersion(v string) Option {
	return func(c *Connector) {
		if v != "" {
			c.apiVersion = v
		}
	}
}

// New returns a Key Vault connector for the vault at vaultURL, authenticating
// with tokens.
func New(vaultURL string, tokens TokenProvider, opts ...Option) *Connector {
	c := &Connector{
		vaultURL:   strings.TrimRight(vaultURL, "/"),
		tokens:     tokens,
		apiVersion: defaultAPIVersion,
	}
	if u, err := url.Parse(vaultURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "azure-keyvault" }

// Capabilities declares the least privilege the connector needs: reach the vault
// host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy imports the renewed key and certificate into the vault certificate
// named by dep.Target.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("azurekv: acquire token: %w", err)
	}
	defer secret.Wipe(token)

	bundle := pemBundle(dep.KeyPEM, dep.CertPEM)
	defer secret.Wipe(bundle)
	reqBody, err := json.Marshal(importRequest{
		Value:  secretjson.Base64Bytes(bundle),
		Policy: policy{SecretProps: secretProps{ContentType: pemContentType}},
	})
	if err != nil {
		return fmt.Errorf("azurekv: encode request: %w", err)
	}
	defer secret.Wipe(reqBody)

	endpoint := c.vaultURL + "/certificates/" + url.PathEscape(dep.Target) + "/import?api-version=" + c.apiVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))

	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("azurekv: import certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("azurekv: import certificate %q: status %d (response body redacted)", dep.Target, resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return nil
}

// Preview authenticates to the vault and lists at most one certificate. It uses
// the exact token provider and sandbox as Deploy, but cannot reach the import
// endpoint and carries no certificate/private-key material.
func (c *Connector) Preview(ctx context.Context, sb connector.Sandbox, target string) (connector.Preview, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return connector.Preview{}, fmt.Errorf("azurekv: acquire preview token: %w", err)
	}
	defer secret.Wipe(token)
	endpoint := c.vaultURL + "/certificates?api-version=" + url.QueryEscape(c.apiVersion) + "&maxresults=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return connector.Preview{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := sb.Request(req)
	if err != nil {
		return connector.Preview{}, fmt.Errorf("azurekv: preview certificate access: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Preview{}, fmt.Errorf("azurekv: preview certificate access: status %d (response body redacted)", resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return connector.Preview{
		Endpoint:    c.vaultURL + "/certificates/" + url.PathEscape(target),
		WouldMutate: []string{"import a new version of certificate " + target + " with its renewed private key"},
		Detail:      "Azure Key Vault accepted an authenticated read-only certificate list; no certificate version was created",
	}, nil
}

// importRequest is the Key Vault certificate import body.
type importRequest struct {
	Value  secretjson.Base64Bytes `json:"value"`
	Policy policy                 `json:"policy"`
}

type policy struct {
	SecretProps secretProps `json:"secret_props"`
}

type secretProps struct {
	ContentType string `json:"contentType"`
}

// pemBundle concatenates the private key and certificate chain into a single PEM
// (key first), the form Key Vault imports as application/x-pem-file.
func pemBundle(keyPEM, certPEM []byte) []byte {
	var out []byte
	out = append(out, keyPEM...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, certPEM...)
	return out
}
