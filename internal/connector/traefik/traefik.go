// SPDX-License-Identifier: MPL-2.0

// Package traefik is the Traefik file-provider deployment connector. It writes a
// renewed certificate/key pair to the files referenced by Traefik dynamic config;
// Traefik's file watcher observes the change and reloads the credential.
//
// Delivery is outbox-driven through connector.Registry (AN-6). PEM material is
// opaque []byte (AN-8), idempotency is SHA-256 through internal/crypto (AN-3),
// and all filesystem operations are capability-gated by the connector sandbox.
package traefik

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
)

const metricName = "trstctl_traefik_deployments_total"

// Connector writes renewed credentials to Traefik file-provider paths.
type Connector struct {
	certPath string
	keyPath  string
	metrics  *observ.CounterVec
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithMetrics records per-target deployment counters in registry.
func WithMetrics(reg *observ.Registry) Option {
	return func(c *Connector) {
		if reg != nil {
			c.metrics = reg.CounterVec(metricName, "Traefik connector deployments by target and result.", []string{"target", "result"})
		}
	}
}

// New returns a connector that writes certPath and keyPath for Traefik.
func New(certPath, keyPath string, opts ...Option) *Connector {
	c := &Connector{certPath: certPath, keyPath: keyPath}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "traefik" }

// Capabilities declares least privilege: read/write the cert and key paths for
// idempotency and rollback. Traefik needs no command or network capability.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSRead, pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSRead, path.Dir(c.certPath)).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.certPath))
	if d := path.Dir(c.keyPath); d != path.Dir(c.certPath) {
		g = g.WithPathPrefix(pluginhost.CapFSRead, d).WithPathPrefix(pluginhost.CapFSWrite, d)
	}
	return g
}

// Deploy writes cert/key unless the current files already match the renewed
// credential. If the second write fails, the first file is restored.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	oldCert, hadCert, err := readExisting(sb, c.certPath)
	if err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("traefik: read current certificate: %w", err)
	}
	oldKey, hadKey, err := readExisting(sb, c.keyPath)
	if err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("traefik: read current key: %w", err)
	}
	if sameDeployment(oldCert, hadCert, oldKey, hadKey, dep) {
		c.observe(dep.Target, "noop")
		return nil
	}
	if err := sb.WriteFile(c.certPath, dep.CertPEM); err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("traefik: write certificate: %w", err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := sb.WriteFile(c.keyPath, dep.KeyPEM); err != nil {
			rollbackErr := c.rollback(sb, oldCert, hadCert, oldKey, hadKey)
			c.observe(dep.Target, "rollback")
			if rollbackErr != nil {
				return fmt.Errorf("traefik: write key failed and rollback failed: write=%w rollback=%v", err, rollbackErr)
			}
			return fmt.Errorf("traefik: write key failed; rollback complete: %w", err)
		}
	}
	c.observe(dep.Target, "deployed")
	return nil
}

func readExisting(sb connector.Sandbox, file string) ([]byte, bool, error) {
	b, err := sb.ReadFile(file)
	if err == nil {
		return b, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func sameDeployment(oldCert []byte, hadCert bool, oldKey []byte, hadKey bool, dep connector.Deployment) bool {
	if !hadCert || crypto.SHA256Hex(oldCert) != dep.Fingerprint {
		return false
	}
	if len(dep.KeyPEM) == 0 {
		return true
	}
	return hadKey && bytes.Equal(oldKey, dep.KeyPEM)
}

func (c *Connector) rollback(sb connector.Sandbox, oldCert []byte, hadCert bool, oldKey []byte, hadKey bool) error {
	if hadCert {
		if err := sb.WriteFile(c.certPath, oldCert); err != nil {
			return fmt.Errorf("restore certificate: %w", err)
		}
	}
	if hadKey {
		if err := sb.WriteFile(c.keyPath, oldKey); err != nil {
			return fmt.Errorf("restore key: %w", err)
		}
	}
	return nil
}

func (c *Connector) observe(target, result string) {
	if c.metrics != nil {
		c.metrics.WithLabelValues(target, result).Inc()
	}
}
