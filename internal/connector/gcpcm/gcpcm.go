// SPDX-License-Identifier: BUSL-1.1

// Package gcpcm is the GCP Certificate Manager deployment connector (S5.13), the
// last cloud certificate store, built from the connector SDK (S5.5). A renewed
// credential is deployed by updating a self-managed Certificate resource
// (certificates.patch with updateMask=self_managed), replacing its
// pemCertificate and pemPrivateKey — the in-place renewal path.
//
// A target that names a certificate map entry (A58) takes the re-bind path
// instead: each deploy creates a fingerprint-named Certificate resource
// (certificates.create) and points the entry at it
// (certificateMapEntries.patch with updateMask=certificates). The predecessor
// resource stays in the project, so a rollback re-points the entry back to it
// without uploading anything, and a readback asks the entry what it serves.
// That is the same discipline the appliance families use: an API that
// addresses an installed object separately from uploading one can roll back.
//
// Like the AWS ACM and Azure Key Vault connectors, and unlike the GCP CAS
// *issuance* plugin (internal/ca/gcpcas) which models the operation behind a
// pure-Go seam and leaves OAuth2 auth to the GCP SDK, a deployment connector must
// route every privileged operation through the capability-gated Sandbox so it is
// conformance-tested and outbox-delivered. So it speaks the Certificate Manager
// REST API directly — an HTTPS PATCH through sb.Request — authenticated with a
// Google OAuth2 bearer token from a TokenProvider seam (StaticToken, or the
// metadata-server MetadataToken in token.go). Bearer auth needs no request
// signing, so this connector imports no crypto/* (AN-3).
//
// certificates.patch is a long-running operation, so the connector polls it to
// completion rather than assuming synchronous success. The PEM credential is
// carried as []byte (AN-8) and treated as opaque.
package gcpcm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultEndpoint  = "https://certificatemanager.googleapis.com"
	defaultPollEvery = time.Second
	defaultMaxPolls  = 60
)

// Connector updates self-managed certificates in GCP Certificate Manager.
type Connector struct {
	endpoint     string // base URL, no trailing slash
	host         string // host of endpoint, for the net.dial grant
	project      string
	location     string
	tokens       TokenProvider
	pollInterval time.Duration
	maxPolls     int
	mapEntry     CertificateMapEntry // zero keeps the in-place patch under the target name
}

var (
	_ connector.Connector  = (*Connector)(nil)
	_ connector.Rollbacker = (*Connector)(nil)
	_ connector.Readbacker = (*Connector)(nil)
)

// CertificateMapEntry names the certificate map entry a deploy points at the
// fingerprint-named certificate and a rollback points back (A58).
type CertificateMapEntry struct {
	Map   string
	Entry string
}

// configured reports whether a map entry was set.
func (e CertificateMapEntry) configured() bool { return e.Map != "" && e.Entry != "" }

// maxTargetWithFingerprint is the longest target id that still leaves room for
// "-" plus the twelve-character fingerprint suffix inside Certificate
// Manager's 63-character resource id limit.
const maxTargetWithFingerprint = 50

// ParseCertificateMapEntry validates an operator-supplied certificate_map_entry
// value of the form "map/entry": two Certificate Manager resource ids
// separated by a single slash.
func ParseCertificateMapEntry(value string) (CertificateMapEntry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CertificateMapEntry{}, nil
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !validResourceID(parts[0]) || !validResourceID(parts[1]) {
		return CertificateMapEntry{}, errors.New("gcpcm: certificate_map_entry must be \"<certificate-map>/<entry>\" using lowercase Certificate Manager resource ids")
	}
	return CertificateMapEntry{Map: parts[0], Entry: parts[1]}, nil
}

// validResourceID applies Certificate Manager's id rule: 1-63 characters,
// lowercase letters, digits and hyphens, starting with a letter and not ending
// with a hyphen.
func validResourceID(id string) bool {
	if id == "" || len(id) > 63 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		case r == '-':
			if i == 0 || i == len(id)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// WithCertificateMapEntry makes deploys fingerprint-named and bound to the
// given certificate map entry, which is what makes the target rollback-capable.
// A zero entry keeps the in-place patch.
func WithCertificateMapEntry(entry CertificateMapEntry) Option {
	return func(c *Connector) { c.mapEntry = entry }
}

// Option configures a Connector.
type Option func(*Connector)

// WithEndpoint overrides the Certificate Manager base URL (for tests or private
// service endpoints).
func WithEndpoint(endpoint string) Option {
	return func(c *Connector) { c.setEndpoint(endpoint) }
}

// WithPollInterval sets the delay between operation polls (default 1s; tests use
// 0).
func WithPollInterval(d time.Duration) Option {
	return func(c *Connector) {
		if d < 0 {
			d = 0
		}
		c.pollInterval = d
	}
}

// New returns a Certificate Manager connector for the given project and location,
// authenticating with tokens.
func New(project, location string, tokens TokenProvider, opts ...Option) *Connector {
	c := &Connector{
		project:      project,
		location:     location,
		tokens:       tokens,
		pollInterval: defaultPollEvery,
		maxPolls:     defaultMaxPolls,
	}
	c.setEndpoint(defaultEndpoint)
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Connector) setEndpoint(endpoint string) {
	c.endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		c.host = u.Host
	}
}

// Name identifies the connector.
func (c *Connector) Name() string { return "gcp-certificate-manager" }

// Capabilities declares the least privilege the connector needs: reach the
// Certificate Manager host over the network. No filesystem, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy replaces the self-managed certificate named by dep.Target with the
// renewed chain and key, then waits for the resulting operation to complete.
// With a certificate map entry configured it instead creates a
// fingerprint-named certificate and points the entry at it, leaving the
// predecessor in place for a rollback.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if c.mapEntry.configured() {
		return c.deployAndBind(ctx, sb, dep)
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcpcm: acquire token: %w", err)
	}
	defer secret.Wipe(token)

	body, err := json.Marshal(patchRequest{SelfManaged: selfManaged{
		PEMCertificate: secretjson.StringBytes(dep.CertPEM),
		PEMPrivateKey:  secretjson.StringBytes(dep.KeyPEM),
	}})
	if err != nil {
		return fmt.Errorf("gcpcm: encode request: %w", err)
	}

	endpoint := c.certificateURL(dep.Target) + "?updateMask=self_managed"
	op, err := c.call(ctx, sb, http.MethodPatch, endpoint, token, body)
	secret.Wipe(body)
	if err != nil {
		return fmt.Errorf("gcpcm: update certificate %q: %w", dep.Target, err)
	}
	return c.awaitOperation(ctx, sb, token, op)
}

// deployAndBind is the re-bind deploy (A58): create the fingerprint-named
// certificate (an id that already exists is the same certificate from an
// earlier attempt and is reused), then point the map entry at it.
func (c *Connector) deployAndBind(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	name, err := c.deployedCertificateID(dep.Target, dep.Fingerprint)
	if err != nil {
		return err
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcpcm: acquire token: %w", err)
	}
	defer secret.Wipe(token)

	body, err := json.Marshal(patchRequest{SelfManaged: selfManaged{
		PEMCertificate: secretjson.StringBytes(dep.CertPEM),
		PEMPrivateKey:  secretjson.StringBytes(dep.KeyPEM),
	}})
	if err != nil {
		return fmt.Errorf("gcpcm: encode request: %w", err)
	}
	endpoint := c.certificatesURL() + "?certificateId=" + url.QueryEscape(name)
	op, err := c.call(ctx, sb, http.MethodPost, endpoint, token, body)
	secret.Wipe(body)
	switch {
	case errors.Is(err, errAlreadyExists):
		// The same certificate computes the same id, so a retry after a lost
		// response finds its own earlier create. Binding below is idempotent.
	case err != nil:
		return fmt.Errorf("gcpcm: create certificate %q: %w", name, err)
	default:
		if err := c.awaitOperation(ctx, sb, token, op); err != nil {
			return fmt.Errorf("gcpcm: create certificate %q: %w", name, err)
		}
	}
	if err := c.bind(ctx, sb, token, name); err != nil {
		return fmt.Errorf("gcpcm: bind map entry %s/%s to %q: %w", c.mapEntry.Map, c.mapEntry.Entry, name, err)
	}
	return nil
}

// Rollback re-points the configured certificate map entry at the predecessor's
// fingerprint-named certificate, which must still exist in the project (A58).
// No certificate or key is uploaded.
func (c *Connector) Rollback(ctx context.Context, sb connector.Sandbox, rb connector.Rollback) error {
	if !c.mapEntry.configured() {
		return connector.ErrRollbackNotConfigured
	}
	if strings.TrimSpace(rb.PredecessorFingerprint) == "" {
		return connector.ErrNoPredecessorInstalled
	}
	name, err := c.deployedCertificateID(rb.Target, rb.PredecessorFingerprint)
	if err != nil {
		return err
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcpcm: acquire token: %w", err)
	}
	defer secret.Wipe(token)
	if err := c.mustExist(ctx, sb, token, c.certificateURL(name)); err != nil {
		return fmt.Errorf("gcpcm: predecessor certificate %q: %w", name, err)
	}
	if err := c.bind(ctx, sb, token, name); err != nil {
		return fmt.Errorf("gcpcm: re-bind map entry %s/%s to predecessor %q: %w", c.mapEntry.Map, c.mapEntry.Entry, name, err)
	}
	return nil
}

// Readback reports the certificate the configured map entry points at (A58).
// It asks Certificate Manager, not the deploy: an entry re-pointed by hand is
// reported as diverged, not as clean.
func (c *Connector) Readback(ctx context.Context, sb connector.Sandbox, _ string) (connector.Installed, error) {
	if !c.mapEntry.configured() {
		return connector.Installed{}, connector.ErrReadbackNotConfigured
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("gcpcm: acquire token: %w", err)
	}
	defer secret.Wipe(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.mapEntryURL(), nil)
	if err != nil {
		return connector.Installed{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := sb.Request(req)
	if err != nil {
		return connector.Installed{}, fmt.Errorf("gcpcm: read back map entry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Installed{}, fmt.Errorf("gcpcm: read back map entry: status %d (response body redacted)", resp.StatusCode)
	}
	var body struct {
		Certificates []string `json:"certificates"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return connector.Installed{}, fmt.Errorf("gcpcm: decode map entry: %w", err)
	}
	entry := c.mapEntry.Map + "/" + c.mapEntry.Entry
	if len(body.Certificates) == 0 {
		return connector.Installed{ObjectName: entry}, nil
	}
	resource := body.Certificates[0]
	name := resource[strings.LastIndex(resource, "/")+1:]
	return connector.Installed{Fingerprint: connector.FingerprintFromObjectName(name), ObjectName: name, Bound: true}, nil
}

// deployedCertificateID derives the fingerprint-named certificate id and
// refuses a target that cannot carry the suffix inside the 63-character limit.
func (c *Connector) deployedCertificateID(target, fingerprint string) (string, error) {
	target = strings.TrimSpace(target)
	if len(target) > maxTargetWithFingerprint || !validResourceID(target) {
		return "", fmt.Errorf("gcpcm: a map-entry target must be a Certificate Manager id of %d characters or fewer so its fingerprint-named certificates fit the 63-character limit", maxTargetWithFingerprint)
	}
	name := connector.DeployedObjectName(target, fingerprint)
	if !validResourceID(name) {
		return "", fmt.Errorf("gcpcm: derived certificate id %q is not a valid Certificate Manager id", name)
	}
	return name, nil
}

// bind points the map entry at the named certificate and waits for the
// operation. It carries no certificate or key.
func (c *Connector) bind(ctx context.Context, sb connector.Sandbox, token []byte, name string) error {
	body, err := json.Marshal(map[string][]string{"certificates": {c.certificateResource(name)}})
	if err != nil {
		return err
	}
	op, err := c.call(ctx, sb, http.MethodPatch, c.mapEntryURL()+"?updateMask=certificates", token, body)
	if err != nil {
		return err
	}
	return c.awaitOperation(ctx, sb, token, op)
}

// mustExist answers ErrNoPredecessorInstalled for a 404 so the caller can say
// the predecessor is gone rather than that the API failed.
func (c *Connector) mustExist(ctx context.Context, sb connector.Sandbox, token []byte, endpoint string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
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

func (c *Connector) certificatesURL() string {
	return c.endpoint + "/v1/projects/" + url.PathEscape(c.project) + "/locations/" + url.PathEscape(c.location) + "/certificates"
}

func (c *Connector) certificateURL(id string) string {
	return c.certificatesURL() + "/" + url.PathEscape(id)
}

func (c *Connector) certificateResource(id string) string {
	return "projects/" + c.project + "/locations/" + c.location + "/certificates/" + id
}

func (c *Connector) mapEntryURL() string {
	return c.endpoint + "/v1/projects/" + url.PathEscape(c.project) + "/locations/" + url.PathEscape(c.location) +
		"/certificateMaps/" + url.PathEscape(c.mapEntry.Map) + "/certificateMapEntries/" + url.PathEscape(c.mapEntry.Entry)
}

// errAlreadyExists is the create outcome for an id that is already in the
// project.
var errAlreadyExists = errors.New("gcpcm: certificate already exists")

// Preview authenticates to Certificate Manager and lists at most one resource
// inside the exact project/location scope. It never calls certificates.patch or
// polls a mutation operation.
func (c *Connector) Preview(ctx context.Context, sb connector.Sandbox, target string) (connector.Preview, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return connector.Preview{}, fmt.Errorf("gcpcm: acquire preview token: %w", err)
	}
	defer secret.Wipe(token)
	collection := fmt.Sprintf("%s/v1/projects/%s/locations/%s/certificates", c.endpoint, url.PathEscape(c.project), url.PathEscape(c.location))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, collection+"?pageSize=1", nil)
	if err != nil {
		return connector.Preview{}, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := sb.Request(req)
	if err != nil {
		return connector.Preview{}, fmt.Errorf("gcpcm: preview certificate access: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return connector.Preview{}, fmt.Errorf("gcpcm: preview certificate access: status %d (response body redacted)", resp.StatusCode)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	resource := collection + "/" + url.PathEscape(target)
	return connector.Preview{
		Endpoint:    resource,
		WouldMutate: []string{"replace the self-managed certificate and private key on " + resource},
		Detail:      "GCP accepted an authenticated read-only certificate list in the configured project and location; no certificate was patched",
	}, nil
}

// awaitOperation polls op until it reports done. An operation with no name (for
// example a synchronous response) is treated as already complete.
func (c *Connector) awaitOperation(ctx context.Context, sb connector.Sandbox, token []byte, op operation) error {
	for polls := 0; ; polls++ {
		if op.Name == "" || op.Done {
			return nil
		}
		if polls >= c.maxPolls {
			return fmt.Errorf("gcpcm: operation %s did not complete after %d polls", op.Name, polls)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.pollInterval):
		}
		var err error
		op, err = c.call(ctx, sb, http.MethodGet, c.endpoint+"/v1/"+op.Name, token, nil)
		if err != nil {
			return fmt.Errorf("gcpcm: poll operation: %w", err)
		}
	}
}

// call performs a request through the sandbox and returns the parsed operation.
// Empty 2xx bodies are treated as synchronous completion; malformed JSON is a
// hard error because accepting it would hide a broken Certificate Manager
// response behind a zero operation.
func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, endpoint string, token []byte, body []byte) (operation, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return operation{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))

	resp, err := sb.Request(req)
	if err != nil {
		return operation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict && method == http.MethodPost {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return operation{}, errAlreadyExists
	}
	if resp.StatusCode/100 != 2 {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return operation{}, fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
	}
	data, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return operation{}, fmt.Errorf("read response (details redacted)")
	}
	defer secret.Wipe(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return operation{}, nil
	}
	var op operation
	if err := json.Unmarshal(data, &op); err != nil {
		return operation{}, fmt.Errorf("decode operation response failed (details redacted)")
	}
	return op, nil
}

type patchRequest struct {
	SelfManaged selfManaged `json:"selfManaged"`
}

type selfManaged struct {
	PEMCertificate secretjson.StringBytes `json:"pemCertificate"`
	PEMPrivateKey  secretjson.StringBytes `json:"pemPrivateKey"`
}

type operation struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}
