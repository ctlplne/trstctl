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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
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

	bundle := pemBundle(dep.KeyPEM, dep.CertPEM)
	reqBody, err := json.Marshal(importRequest{
		Value:  base64.StdEncoding.EncodeToString(bundle),
		Policy: policy{SecretProps: secretProps{ContentType: pemContentType}},
	})
	if err != nil {
		return fmt.Errorf("azurekv: encode request: %w", err)
	}

	endpoint := c.vaultURL + "/certificates/" + url.PathEscape(dep.Target) + "/import?api-version=" + c.apiVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("azurekv: import certificate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("azurekv: import certificate %q: status %d: %s", dep.Target, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return nil
}

// importRequest is the Key Vault certificate import body.
type importRequest struct {
	Value  string `json:"value"`
	Policy policy `json:"policy"`
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
	out := make([]byte, 0, len(keyPEM)+len(certPEM)+1)
	out = append(out, keyPEM...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, certPEM...)
	return out
}
