// SPDX-License-Identifier: MPL-2.0

// Package envoy is the Envoy SDS push deployment connector. It sends a renewed
// certificate/key pair to an explicit SDS-management endpoint; it does not
// implement or call the SPIFFE Workload API pull path.
//
// Delivery is outbox-driven through connector.Registry (AN-6). PEM material is
// carried as []byte (AN-8), idempotency uses Deployment.Fingerprint from the
// crypto boundary (AN-3), and every network call is capability-gated.
package envoy

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
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/secretjson"
)

const (
	metricName = "trstctl_envoy_deployments_total"
	secretType = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
)

// Connector pushes TLS secrets into an Envoy SDS-management endpoint.
type Connector struct {
	baseURL    string
	host       string
	secretName string
	metrics    *observ.CounterVec
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithMetrics records per-target deployment counters in registry.
func WithMetrics(reg *observ.Registry) Option {
	return func(c *Connector) {
		if reg != nil {
			c.metrics = reg.CounterVec(metricName, "Envoy SDS connector deployments by target and result.", []string{"target", "result"})
		}
	}
}

// New returns an Envoy SDS push connector for baseURL and secretName.
func New(baseURL, secretName string, opts ...Option) *Connector {
	c := &Connector{baseURL: strings.TrimRight(baseURL, "/"), secretName: secretName}
	if u, err := url.Parse(baseURL); err == nil {
		c.host = u.Host
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "envoy" }

// Capabilities declares least privilege: the connector only reaches its SDS
// management endpoint. It does not read/write local files or execute commands.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, c.host)
}

// Deploy pushes dep as an Envoy SDS Secret. A matching current secret is a no-op;
// if the endpoint applies an update and then reports failure, the previous SDS
// secret is pushed back.
func (c *Connector) Deploy(ctx context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := c.validate(); err != nil {
		c.observe(dep.Target, "invalid_config")
		return err
	}
	current, hadCurrent, err := c.current(ctx, sb)
	if err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("envoy: read current SDS secret: %w", err)
	}
	defer wipeResource(&current)
	desired := resourceFromDeployment(c.secretName, dep)
	if hadCurrent && sameSecret(current, desired) {
		c.observe(dep.Target, "noop")
		return nil
	}
	if err := c.put(ctx, sb, desired); err != nil {
		if hadCurrent {
			rbErr := c.put(ctx, sb, current)
			c.observe(dep.Target, "rollback")
			if rbErr != nil {
				return fmt.Errorf("envoy: SDS update failed and rollback failed: update=%w rollback=%v", err, rbErr)
			}
			return fmt.Errorf("envoy: SDS update failed; rollback complete: %w", err)
		}
		c.observe(dep.Target, "error")
		return fmt.Errorf("envoy: SDS update failed: %w", err)
	}
	c.observe(dep.Target, "deployed")
	return nil
}

func (c *Connector) validate() error {
	if c.baseURL == "" {
		return fmt.Errorf("envoy: SDS endpoint URL is required")
	}
	if c.host == "" {
		return fmt.Errorf("envoy: SDS endpoint URL must include a host")
	}
	if c.secretName == "" {
		return fmt.Errorf("envoy: SDS secret name is required")
	}
	if strings.ContainsAny(c.secretName, "/\\\x00\r\n") {
		return fmt.Errorf("envoy: SDS secret name %q must not contain path separators or control bytes", c.secretName)
	}
	return nil
}

func (c *Connector) current(ctx context.Context, sb connector.Sandbox) (sdsResource, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.secretURL(), nil)
	if err != nil {
		return sdsResource{}, false, err
	}
	resp, err := sb.Request(req)
	if err != nil {
		return sdsResource{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_ = secret.DrainBounded(resp.Body, 4<<10)
		return sdsResource{}, false, nil
	}
	if resp.StatusCode/100 != 2 {
		return sdsResource{}, false, responseError(resp)
	}
	data, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return sdsResource{}, false, fmt.Errorf("read SDS secret (details redacted)")
	}
	defer secret.Wipe(data)
	var res sdsResource
	if err := json.Unmarshal(data, &res); err != nil {
		wipeResource(&res)
		return sdsResource{}, false, fmt.Errorf("decode SDS secret failed (details redacted)")
	}
	return res, true, nil
}

func (c *Connector) put(ctx context.Context, sb connector.Sandbox, res sdsResource) error {
	body, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("encode SDS secret: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.secretURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := sb.Request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return responseError(resp)
	}
	_ = secret.DrainBounded(resp.Body, 1<<20)
	return nil
}

func (c *Connector) secretURL() string {
	return c.baseURL + "/v1/sds/secrets/" + url.PathEscape(c.secretName)
}

func responseError(resp *http.Response) error {
	_ = secret.DrainBounded(resp.Body, 4<<10)
	return fmt.Errorf("status %d (response body redacted)", resp.StatusCode)
}

func sameSecret(a, b sdsResource) bool {
	if len(a.Resources) != 1 || len(b.Resources) != 1 {
		return false
	}
	as := a.Resources[0]
	bs := b.Resources[0]
	return as.Type == bs.Type &&
		as.Name == bs.Name &&
		as.Fingerprint == bs.Fingerprint &&
		bytes.Equal(as.TLSCertificate.CertificateChain.InlineBytes, bs.TLSCertificate.CertificateChain.InlineBytes) &&
		bytes.Equal(as.TLSCertificate.PrivateKey.InlineBytes, bs.TLSCertificate.PrivateKey.InlineBytes)
}

func (c *Connector) observe(target, result string) {
	if c.metrics != nil {
		c.metrics.WithLabelValues(target, result).Inc()
	}
}

func resourceFromDeployment(name string, dep connector.Deployment) sdsResource {
	return sdsResource{Resources: []sdsSecret{{
		Type:        secretType,
		Name:        name,
		Fingerprint: dep.Fingerprint,
		TLSCertificate: tlsCertificate{
			CertificateChain: dataSource{InlineBytes: secretjson.Base64Bytes(dep.CertPEM)},
			PrivateKey:       dataSource{InlineBytes: secretjson.Base64Bytes(dep.KeyPEM)},
		},
	}}}
}

// wipeResource destroys key-bearing byte slices decoded from the remote SDS
// endpoint. Desired resources alias the caller-owned deployment and therefore
// are never passed here; this helper owns only response-decoder allocations.
func wipeResource(res *sdsResource) {
	if res == nil {
		return
	}
	for i := range res.Resources {
		secret.Wipe(res.Resources[i].TLSCertificate.CertificateChain.InlineBytes)
		secret.Wipe(res.Resources[i].TLSCertificate.PrivateKey.InlineBytes)
		res.Resources[i].TLSCertificate.CertificateChain.InlineBytes = nil
		res.Resources[i].TLSCertificate.PrivateKey.InlineBytes = nil
	}
}

type sdsResource struct {
	Resources []sdsSecret `json:"resources"`
}

type sdsSecret struct {
	Type           string         `json:"@type"`
	Name           string         `json:"name"`
	Fingerprint    string         `json:"fingerprint"`
	TLSCertificate tlsCertificate `json:"tls_certificate"`
}

type tlsCertificate struct {
	CertificateChain dataSource `json:"certificate_chain"`
	PrivateKey       dataSource `json:"private_key"`
}

type dataSource struct {
	InlineBytes secretjson.Base64Bytes `json:"inline_bytes"`
}
