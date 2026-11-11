// SPDX-License-Identifier: BUSL-1.1

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
// opaque. The import marks the key exportable, which is Key Vault's own default
// for an import, stated so a rollback can serve the predecessor again.
//
// Rollback (A166-L1): Key Vault keeps every imported version but serves the
// newest to anything that reads the certificate by name, and has no call that
// makes an older version current. The connector finds the predecessor's
// version by its fingerprint, reads that version's secret (its key and chain,
// which the vault returns only for an exportable key) and imports it again as
// the newest version. The predecessor's key comes from the vault's own copy;
// trstctl holds none. Readback reports the fingerprint of the version the
// vault serves now.
package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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

const (
	defaultAPIVersion = "7.4"
	pemContentType    = "application/x-pem-file"
	pfxContentType    = "application/x-pkcs12"
	// maxRollbackVersions bounds how far back a rollback looks for the
	// predecessor's version.
	maxRollbackVersions = 100
)

// Connector imports renewed certificates into Azure Key Vault.
type Connector struct {
	vaultURL   string // base URL, e.g. https://myvault.vault.azure.net (no trailing slash)
	host       string // host of vaultURL, for the net.dial grant
	tokens     TokenProvider
	apiVersion string
}

var (
	_ connector.Connector  = (*Connector)(nil)
	_ connector.Rollbacker = (*Connector)(nil)
	_ connector.Readbacker = (*Connector)(nil)
)

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
	return c.importBundle(ctx, sb, token, dep.Target, secretjson.Base64Bytes(bundle), pemContentType)
}

// importBundle imports value (the import body's "value": base64 of a PEM
// bundle, or a PKCS#12 secret's own base64 text) as a new version of the
// certificate named target, with an exportable key.
func (c *Connector) importBundle(ctx context.Context, sb connector.Sandbox, token []byte, target string, value json.Marshaler, contentType string) error {
	exportable := true
	reqBody, err := json.Marshal(struct {
		Value  json.Marshaler `json:"value"`
		Policy policy         `json:"policy"`
	}{value, policy{KeyProps: &keyProps{Exportable: &exportable}, SecretProps: secretProps{ContentType: contentType}}})
	if err != nil {
		return fmt.Errorf("azurekv: encode request: %w", err)
	}
	defer secret.Wipe(reqBody)

	endpoint := c.vaultURL + "/certificates/" + url.PathEscape(target) + "/import?api-version=" + c.apiVersion
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
		return fmt.Errorf("azurekv: import certificate %q: status %d (response body redacted)", target, resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return nil
}

// Rollback makes the predecessor the certificate's current version again
// (A166-L1): it finds the version whose leaf has the predecessor's
// fingerprint, reads that version's secret and imports it as the newest
// version. It fails, and imports nothing, when no retained version is the
// predecessor (ErrNoPredecessorInstalled) or the vault will not return its
// key.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	want := strings.ToLower(strings.TrimSpace(rb.PredecessorFingerprint))
	if want == "" {
		return connector.ErrNoPredecessorInstalled
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("azurekv: acquire token: %w", err)
	}
	defer secret.Wipe(token)
	versions, err := c.versionIDs(ctx, sb, token, rb.Target)
	if err != nil {
		return err
	}
	for _, version := range versions {
		fingerprint, err := c.versionFingerprint(ctx, sb, token, rb.Target, version)
		if err != nil {
			return err
		}
		if fingerprint != want {
			continue
		}
		value, contentType, err := c.versionSecret(ctx, sb, token, rb.Target, version)
		if err != nil {
			return err
		}
		defer secret.Wipe(value)
		var importValue json.Marshaler = secretjson.Base64Bytes(value)
		if contentType == pfxContentType {
			// A PKCS#12 secret is already the base64 text the import takes.
			importValue = rawJSONString(value)
		}
		if err := c.importBundle(ctx, sb, token, rb.Target, importValue, contentType); err != nil {
			return fmt.Errorf("azurekv: re-import predecessor version %s: %w", version, err)
		}
		return nil
	}
	return connector.ErrNoPredecessorInstalled
}

// Readback reports the certificate version the vault serves by name now.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, target string) (connector.Installed, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("azurekv: acquire token: %w", err)
	}
	defer secret.Wipe(token)
	fingerprint, err := c.versionFingerprint(ctx, sb, token, target, "")
	if err != nil {
		return connector.Installed{}, err
	}
	return connector.Installed{Fingerprint: fingerprint, ObjectName: target, Bound: true}, nil
}

// versionIDs lists the certificate's version ids, newest first as the vault
// returns them, following nextLink up to maxRollbackVersions.
func (c *Connector) versionIDs(ctx context.Context, sb connector.Sandbox, token []byte, target string) ([]string, error) {
	next := c.vaultURL + "/certificates/" + url.PathEscape(target) + "/versions?api-version=" + url.QueryEscape(c.apiVersion)
	var out []string
	for next != "" && len(out) < maxRollbackVersions {
		if !strings.HasPrefix(next, c.vaultURL+"/") {
			return nil, errors.New("azurekv: a version page link left the vault")
		}
		var page struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink *string `json:"nextLink"`
		}
		if err := c.getJSON(ctx, sb, token, next, "list certificate versions", &page); err != nil {
			return nil, err
		}
		for _, item := range page.Value {
			if i := strings.LastIndex(item.ID, "/"); i >= 0 && i+1 < len(item.ID) {
				out = append(out, item.ID[i+1:])
			}
		}
		next = ""
		if page.NextLink != nil {
			next = *page.NextLink
		}
	}
	return out, nil
}

// versionFingerprint is the SHA-256 of one version's leaf (its "cer"); an
// empty version is the current one.
func (c *Connector) versionFingerprint(ctx context.Context, sb connector.Sandbox, token []byte, target, version string) (string, error) {
	endpoint := c.vaultURL + "/certificates/" + url.PathEscape(target)
	if version != "" {
		endpoint += "/" + url.PathEscape(version)
	}
	var bundle struct {
		Cer string `json:"cer"`
	}
	if err := c.getJSON(ctx, sb, token, endpoint+"?api-version="+url.QueryEscape(c.apiVersion), "read certificate", &bundle); err != nil {
		return "", err
	}
	der, err := base64.StdEncoding.DecodeString(bundle.Cer)
	if err != nil || len(der) == 0 {
		return "", errors.New("azurekv: the vault returned a certificate without its DER")
	}
	return connector.CertificateFingerprint(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// versionSecret reads one version's secret: its key and chain, as the vault
// stored them. The vault refuses it for a key that is not exportable.
func (c *Connector) versionSecret(ctx context.Context, sb connector.Sandbox, token []byte, target, version string) ([]byte, string, error) {
	endpoint := c.vaultURL + "/secrets/" + url.PathEscape(target) + "/" + url.PathEscape(version) + "?api-version=" + url.QueryEscape(c.apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := sb.Request(req)
	if err != nil {
		return nil, "", fmt.Errorf("azurekv: read predecessor version secret: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, "", errors.New("azurekv: the vault will not return the predecessor version's key (it is not exportable, or this identity may not read secrets)")
	}
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, "", fmt.Errorf("azurekv: read predecessor version secret: status %d (response body redacted)", resp.StatusCode)
	}
	raw, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, "", fmt.Errorf("azurekv: read predecessor version secret: %w", err)
	}
	defer secret.Wipe(raw)
	var body struct {
		Value       secretjson.StringBytes `json:"value"`
		ContentType string                 `json:"contentType"`
	}
	// Closure: the field is nil until decoded, so a bare defer would wipe nothing.
	defer func() { secret.Wipe(body.Value) }()
	if err := json.Unmarshal(raw, &body); err != nil || len(body.Value) == 0 {
		return nil, "", errors.New("azurekv: the predecessor version's secret is empty or unreadable")
	}
	if body.ContentType != pemContentType && body.ContentType != pfxContentType {
		return nil, "", fmt.Errorf("azurekv: the predecessor version's secret has content type %q, not a certificate bundle", body.ContentType)
	}
	return append([]byte(nil), body.Value...), body.ContentType, nil
}

// getJSON GETs a bounded JSON document from the vault.
func (c *Connector) getJSON(ctx context.Context, sb connector.Sandbox, token []byte, endpoint, what string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := sb.Request(req)
	if err != nil {
		return fmt.Errorf("azurekv: %s: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("azurekv: %s: status %d (response body redacted)", what, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("azurekv: %s: %w", what, err)
	}
	return nil
}

// rawJSONString marshals base64 text as a JSON string as it is, without a
// string copy of the secret.
type rawJSONString []byte

func (r rawJSONString) MarshalJSON() ([]byte, error) {
	for _, b := range r {
		if !base64Text(b) {
			return nil, errors.New("azurekv: a PKCS#12 secret is not base64 text")
		}
	}
	out := make([]byte, 0, len(r)+2)
	out = append(out, '"')
	out = append(out, r...)
	return append(out, '"'), nil
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

type policy struct {
	KeyProps    *keyProps   `json:"key_props,omitempty"`
	SecretProps secretProps `json:"secret_props"`
}

type keyProps struct {
	Exportable *bool `json:"exportable,omitempty"`
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

// base64Text reports whether b belongs to the standard base64 alphabet.
func base64Text(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	default:
		return b == '+' || b == '/' || b == '='
	}
}
