// Package gcpcm is the GCP Certificate Manager deployment connector (S5.13), the
// last cloud certificate store, built from the connector SDK (S5.5). A renewed
// credential is deployed by updating a self-managed Certificate resource
// (certificates.patch with updateMask=self_managed), replacing its
// pemCertificate and pemPrivateKey — the in-place renewal path.
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
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
}

var _ connector.Connector = (*Connector)(nil)

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
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("gcpcm: acquire token: %w", err)
	}

	body, err := json.Marshal(patchRequest{SelfManaged: selfManaged{
		PEMCertificate: string(dep.CertPEM),
		PEMPrivateKey:  string(dep.KeyPEM),
	}})
	if err != nil {
		return fmt.Errorf("gcpcm: encode request: %w", err)
	}

	endpoint := c.endpoint + "/v1/projects/" + c.project + "/locations/" + c.location +
		"/certificates/" + url.PathEscape(dep.Target) + "?updateMask=self_managed"
	op, err := c.call(ctx, sb, http.MethodPatch, endpoint, token, body)
	if err != nil {
		return fmt.Errorf("gcpcm: update certificate %q: %w", dep.Target, err)
	}
	return c.awaitOperation(ctx, sb, token, op)
}

// awaitOperation polls op until it reports done. An operation with no name (for
// example a synchronous response) is treated as already complete.
func (c *Connector) awaitOperation(ctx context.Context, sb connector.Sandbox, token string, op operation) error {
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

// call performs a request through the sandbox and returns the parsed operation
// (best-effort: a body that is not an operation yields the zero operation).
func (c *Connector) call(ctx context.Context, sb connector.Sandbox, method, endpoint, token string, body []byte) (operation, error) {
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
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := sb.Request(req)
	if err != nil {
		return operation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return operation{}, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var op operation
	_ = json.Unmarshal(data, &op)
	return op, nil
}

type patchRequest struct {
	SelfManaged selfManaged `json:"selfManaged"`
}

type selfManaged struct {
	PEMCertificate string `json:"pemCertificate"`
	PEMPrivateKey  string `json:"pemPrivateKey"`
}

type operation struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}
