// SPDX-License-Identifier: BUSL-1.1

// Package paloalto is the Palo Alto Networks (PAN-OS) deployment connector
// (S10.10), built from the connector SDK (S5.5). A PAN-OS firewall (and Panorama)
// is driven over the XML API, so — like the F5 BIG-IP, Citrix ADC, FortiGate, and
// AWS ACM connectors — it routes every privileged operation through the
// capability-gated Sandbox (sb.Request) and is conformance-tested and
// outbox-delivered.
//
// Renewal is the PAN-OS certificate *import*: the renewed material is POSTed to
// the import endpoint, which replaces the named certificate object in place and
// reloads it. PAN-OS imports the certificate and the private key as two separate
// objects under the same certificate-name (category=certificate, then
// category=private-key), so the connector makes one import call per part. Each is
// the same shape: the import parameters travel in the query string
// (type=import&category=…&certificate-name=…&format=pem) and the PEM travels as
// the request body; format=pem means PAN-OS reads the body verbatim. A PAN-OS
// import is idempotent — re-importing the same name overwrites the object with
// identical material — so a redeploy converges to the same firewall state.
//
// Authentication is the PAN-OS API key, presented in the X-PAN-KEY header. It
// crosses the wire on every call and is never logged, never placed in an error,
// and is carried in a field, not in the deployment payload. So this connector
// imports no crypto/* (AN-3): the key is opaque and there is no signing. The
// PAN-OS XML API also signals failure *inside* a 200 response — an HTTP 200 with
// <response status="error"> is a failed import — so a 2xx is necessary but not
// sufficient: the import is accepted only when the status is 2xx and the parsed
// XML envelope reports status="success" (equivalently, does not report a non-
// success status). The parse is a tiny status read, not a certificate parse.
// Least privilege is net.dial to the appliance host alone; no filesystem, no
// exec. Key material is carried as []byte (AN-8) and the PEM is opaque (no
// certificate parse).
package paloalto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secrettext"
)

// defaultName is the certificate object name used when the deployment target does
// not name one.
const defaultName = "trstctl"

// PAN-OS import categories: the certificate and the private key are imported as
// two distinct objects sharing one certificate-name.
const (
	categoryCertificate = "certificate"
	categoryPrivateKey  = "private-key"
)

// Connector deploys certificates to a Palo Alto Networks (PAN-OS) firewall or
// Panorama over the XML API.
type Connector struct {
	baseURL string // PAN-OS management base, e.g. https://fw.example (no trailing slash)
	host    string // host of baseURL, for the net.dial grant
	apiKey  []byte // PAN-OS API key (AN-8-adjacent: never logged)
	// sslTLSProfile is the shared SSL/TLS service profile a deploy points at
	// the imported certificate (A44); empty keeps the legacy in-place import.
	sslTLSProfile string
	// commitAdmin scopes the commit to that administrator's own candidate
	// changes (a PAN-OS partial commit), so a deploy or rollback never pushes
	// unrelated changes another admin staged. Required with sslTLSProfile.
	commitAdmin string
}

// WithSSLTLSProfile makes imports fingerprint-named and bound to the named
// shared SSL/TLS service profile, committed on the firewall as a partial
// commit of commitAdmin's changes, which is what makes the target
// rollback-capable.
func WithSSLTLSProfile(profile, commitAdmin string) Option {
	return func(c *Connector) {
		c.sslTLSProfile = strings.TrimSpace(profile)
		c.commitAdmin = strings.TrimSpace(commitAdmin)
	}
}

func (c *Connector) bindingConfigured() error {
	if c.sslTLSProfile != "" && c.commitAdmin == "" {
		return errors.New("paloalto: ssl_tls_profile requires commit_admin, the administrator whose candidate changes the partial commit pushes")
	}
	return nil
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector. (None are required today — baseURL is the
// endpoint and the host is derived from it — but the variadic keeps the
// constructor forward-compatible with the other connectors.)
type Option func(*Connector)

// New returns a PAN-OS connector for the appliance at baseURL, authenticating
// with the PAN-OS API key. baseURL is the endpoint; the net.dial grant host is
// derived from it.
func New(baseURL string, apiKey []byte, opts ...Option) *Connector {
	c := &Connector{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  secrettext.Clone(apiKey),
	}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close destroys the API key copy owned by this one-shot connector.
func (c *Connector) Close() {
	secret.Wipe(c.apiKey)
	c.apiKey = nil
}

// Name identifies the connector.
func (c *Connector) Name() string { return "paloalto" }

// Capabilities declares the least privilege the connector needs: reach the
// appliance host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy imports the renewed certificate (and, when present, the private key)
// into the PAN-OS certificate object named by dep.Target (default "trstctl").
// The certificate and key are imported as two objects under the same name; the
// key import is skipped when no key is supplied (e.g. when the key already lives
// on the appliance in an HSM).
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name := certName(dep.Target)
	if err := c.bindingConfigured(); err != nil {
		return err
	}
	if c.sslTLSProfile != "" {
		// Fingerprint-named so the predecessor survives the next deploy (A44).
		name = connector.DeployedObjectName(name, dep.Fingerprint)
	}

	if err := c.importPart(ctx, sb, categoryCertificate, name, dep.CertPEM); err != nil {
		return fmt.Errorf("paloalto: import certificate %q: %w", name, err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := c.importPart(ctx, sb, categoryPrivateKey, name, dep.KeyPEM); err != nil {
			return fmt.Errorf("paloalto: import private key for %q: %w", name, err)
		}
	}
	if c.sslTLSProfile == "" {
		return nil
	}
	if err := c.bindAndCommit(ctx, sb, name); err != nil {
		return fmt.Errorf("paloalto: bind SSL/TLS service profile %q to %q: %w", c.sslTLSProfile, name, err)
	}
	return nil
}

// Rollback points the configured SSL/TLS service profile back at the
// predecessor's fingerprint-named certificate and commits (A44). The object
// must still be in the candidate configuration; nothing is imported.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if c.sslTLSProfile == "" {
		return connector.ErrRollbackNotConfigured
	}
	if err := c.bindingConfigured(); err != nil {
		return err
	}
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	if object := strings.TrimSpace(rb.PredecessorKeyObject); object != "" {
		return c.rollbackToApplianceKey(ctx, sb, object, rb.PredecessorFingerprint)
	}
	name := connector.RollbackObjectName(certName(rb.Target), rb.PredecessorFingerprint)
	present, err := c.certificateEntryExists(ctx, sb, name)
	if err != nil {
		return fmt.Errorf("paloalto: predecessor certificate %q: %w", name, err)
	}
	if !present {
		return fmt.Errorf("paloalto: predecessor certificate %q: %w", name, connector.ErrNoPredecessorInstalled)
	}
	if err := c.bindAndCommit(ctx, sb, name); err != nil {
		return fmt.Errorf("paloalto: re-bind SSL/TLS service profile %q to predecessor %q: %w", c.sslTLSProfile, name, err)
	}
	return nil
}

// Readback reports the certificate the configured SSL/TLS service profile is
// set to, as the firewall's configuration states it (A44).
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, _ string) (connector.Installed, error) {
	if c.sslTLSProfile == "" {
		return connector.Installed{}, connector.ErrReadbackNotConfigured
	}
	q := url.Values{}
	q.Set("type", "config")
	q.Set("action", "get")
	q.Set("xpath", "/config/shared/ssl-tls-service-profile/entry[@name='"+c.sslTLSProfile+"']")
	body, err := c.api(ctx, sb, q)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("paloalto: read back SSL/TLS service profile %q: %w", c.sslTLSProfile, err)
	}
	defer secret.Wipe(body)
	name := strings.TrimSpace(betweenBytes(body, "<certificate>", "</certificate>"))
	if name == "" {
		return connector.Installed{ObjectName: c.sslTLSProfile}, nil
	}
	if connector.IsApplianceKeyObjectName(name) {
		// A122: an object the firewall generated the key into is named for its
		// job, not its certificate, so the bound certificate itself is exported
		// and fingerprinted.
		certPEM, blockType, err := c.exportPublic(ctx, sb, name)
		if err != nil {
			return connector.Installed{}, fmt.Errorf("paloalto: read back certificate object %q: %w", name, err)
		}
		if blockType != pemCertificate {
			return connector.Installed{ObjectName: name, Bound: true}, nil
		}
		return connector.Installed{Fingerprint: connector.CertificateFingerprint(certPEM), ObjectName: name, Bound: true}, nil
	}
	return connector.Installed{Fingerprint: connector.FingerprintFromObjectName(name), ObjectName: name, Bound: true}, nil
}

func betweenBytes(body []byte, start, end string) string {
	i := bytes.Index(body, []byte(start))
	if i < 0 {
		return ""
	}
	rest := body[i+len(start):]
	j := bytes.Index(rest, []byte(end))
	if j < 0 {
		return ""
	}
	return string(rest[:j])
}

// certificateEntryExists reports whether the candidate configuration holds a
// certificate object of that name.
func (c *Connector) certificateEntryExists(ctx context.Context, sb connector.Sandbox, name string) (bool, error) {
	q := url.Values{}
	q.Set("type", "config")
	q.Set("action", "get")
	q.Set("xpath", "/config/shared/certificate/entry[@name='"+name+"']")
	body, err := c.api(ctx, sb, q)
	if err != nil {
		return false, err
	}
	present := containsASCIIFold(body, []byte(`<entry name="`+name+`"`)) || containsASCIIFold(body, []byte(`<entry name='`+name+`'`))
	secret.Wipe(body)
	return present, nil
}

// bindAndCommit sets the shared SSL/TLS service profile's certificate and
// commits the candidate configuration so the listener serves it.
func (c *Connector) bindAndCommit(ctx context.Context, sb connector.Sandbox, name string) error {
	set := url.Values{}
	set.Set("type", "config")
	set.Set("action", "set")
	set.Set("xpath", "/config/shared/ssl-tls-service-profile/entry[@name='"+c.sslTLSProfile+"']")
	set.Set("element", "<certificate>"+name+"</certificate>")
	body, err := c.api(ctx, sb, set)
	if err != nil {
		return err
	}
	secret.Wipe(body)
	commit := url.Values{}
	commit.Set("type", "commit")
	commit.Set("cmd", "<commit><partial><admin><member>"+c.commitAdmin+"</member></admin></partial></commit>")
	body, err = c.api(ctx, sb, commit)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	secret.Wipe(body)
	return nil
}

// api performs one PAN-OS XML API call and returns its bounded body; a
// transport failure, non-2xx status or status="error" envelope is an error.
func (c *Connector) api(ctx context.Context, sb connector.Sandbox, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-PAN-KEY", secrettext.String(c.apiKey))
	resp, err := sb.Request(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return nil, fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}
	body, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read response (details redacted)")
	}
	if panFailed(body) {
		secret.Wipe(body)
		return nil, fmt.Errorf("PAN-OS reported failure (response body redacted)")
	}
	return body, nil
}

func (c *Connector) importPart(ctx context.Context, sb connector.Sandbox, category, name string, pem []byte) error {
	q := url.Values{}
	q.Set("type", "import")
	q.Set("category", category)
	q.Set("certificate-name", name)
	q.Set("format", "pem")
	endpoint := c.baseURL + "/api/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(pem))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-pem-file")
	// PAN-OS API key. Never logged, never placed in an error.
	req.Header.Set("X-PAN-KEY", secrettext.String(c.apiKey))

	resp, err := sb.Request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}

	// Bound the read so a hostile/large body cannot blow up memory. PAN-OS error
	// bodies are small XML; the success body is too.
	body, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return fmt.Errorf("read response (details redacted)")
	}
	defer secret.Wipe(body)
	// PAN-OS reports failure inside a 200, so the XML status is authoritative.
	if panFailed(body) {
		return fmt.Errorf("PAN-OS reported failure (response body redacted)")
	}
	return nil
}

// panFailed identifies PAN-OS's failure-in-200 envelope without decoding attacker-
// controlled XML text into immutable strings (AN-8).
func panFailed(body []byte) bool {
	return containsASCIIFold(body, []byte(`status="error"`)) ||
		containsASCIIFold(body, []byte(`status='error'`))
}

func containsASCIIFold(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j, want := range needle {
			got := haystack[i+j]
			if got >= 'A' && got <= 'Z' {
				got += 'a' - 'A'
			}
			if want >= 'A' && want <= 'Z' {
				want += 'a' - 'A'
			}
			if got != want {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// certName derives the certificate object name from the deployment target,
// falling back to the default when the target is empty.
func certName(target string) string {
	if target == "" {
		return defaultName
	}
	return target
}
