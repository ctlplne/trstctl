// SPDX-License-Identifier: MPL-2.0

// Package caddy is the Caddy deployment connector. It installs a renewed
// certificate/key pair into the file paths Caddy watches, then runs a validated
// reload command to activate it.
//
// Deployment is outbox-driven through the connector.Registry (AN-6). This package
// treats PEM as opaque []byte (AN-8), computes idempotency through the crypto
// boundary (AN-3), and uses only capability-gated sandbox operations.
package caddy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
)

const metricName = "trstctl_caddy_deployments_total"

// Connector deploys certificates to a Caddy host using file-mode deployment.
type Connector struct {
	certPath  string
	keyPath   string
	reloadCmd []string
	metrics   *observ.CounterVec
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithReloadCommand sets the argv used to reload Caddy after a successful write.
func WithReloadCommand(cmd []string) Option {
	return func(c *Connector) {
		c.reloadCmd = append([]string(nil), cmd...)
	}
}

// WithMetrics records per-target deployment counters in registry.
func WithMetrics(reg *observ.Registry) Option {
	return func(c *Connector) {
		if reg != nil {
			c.metrics = reg.CounterVec(metricName, "Caddy connector deployments by target and result.", []string{"target", "result"})
		}
	}
}

// New returns a Caddy file connector for certPath/keyPath. Caddy watches these
// paths, and the reload command activates the updated files.
func New(certPath, keyPath string, opts ...Option) *Connector {
	c := &Connector{certPath: certPath, keyPath: keyPath, reloadCmd: []string{"caddy", "reload"}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "caddy" }

// Capabilities declares least privilege: read/write the cert/key paths for
// idempotency and rollback, and run the reload command.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSRead, pluginhost.CapFSWrite, connector.CapExec).
		WithPathPrefix(pluginhost.CapFSRead, path.Dir(c.certPath)).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.certPath))
	if d := path.Dir(c.keyPath); d != path.Dir(c.certPath) {
		g = g.WithPathPrefix(pluginhost.CapFSRead, d).WithPathPrefix(pluginhost.CapFSWrite, d)
	}
	return g
}

// Deploy writes the credential if its certificate SHA-256 differs from the
// current target state, reloads Caddy, and restores prior files if reload fails.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := ValidateReloadCommand(c.reloadCmd); err != nil {
		c.observe(dep.Target, "invalid_reload")
		return err
	}
	oldCert, hadCert, err := readExisting(sb, c.certPath)
	if err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("caddy: read current certificate: %w", err)
	}
	defer secret.Wipe(oldCert)
	oldKey, hadKey, err := readExisting(sb, c.keyPath)
	if err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("caddy: read current key: %w", err)
	}
	defer secret.Wipe(oldKey)
	if sameDeployment(oldCert, hadCert, oldKey, hadKey, dep) {
		c.observe(dep.Target, "noop")
		return nil
	}
	if err := sb.WriteFile(c.certPath, dep.CertPEM); err != nil {
		c.observe(dep.Target, "error")
		return fmt.Errorf("caddy: write certificate: %w", err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := sb.WriteFile(c.keyPath, dep.KeyPEM); err != nil {
			c.observe(dep.Target, "error")
			return fmt.Errorf("caddy: write key: %w", err)
		}
	}
	if err := sb.Exec(c.reloadCmd[0], c.reloadCmd[1:]...); err != nil {
		rollbackErr := c.rollback(sb, oldCert, hadCert, oldKey, hadKey)
		c.observe(dep.Target, "rollback")
		if rollbackErr != nil {
			return fmt.Errorf("caddy: reload failed and rollback failed: reload=%w rollback=%v", err, rollbackErr)
		}
		return fmt.Errorf("caddy: reload failed; rollback complete: %w", err)
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
	if !hadCert || connector.CertificateFingerprint(oldCert) != dep.Fingerprint {
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

// ValidateReloadCommand rejects shell-oriented command strings. The connector
// executes argv directly, but this keeps copied shell pipelines out of config.
func ValidateReloadCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("caddy: reload command is required")
	}
	if err := validateToken("reload command", cmd[0]); err != nil {
		return err
	}
	if shellName(cmd[0]) {
		return fmt.Errorf("caddy: reload command %q is a shell interpreter; configure the caddy binary directly", cmd[0])
	}
	for i, arg := range cmd[1:] {
		if err := validateToken(fmt.Sprintf("reload arg[%d]", i), arg); err != nil {
			return err
		}
	}
	return nil
}

func validateToken(label, value string) error {
	if value == "" {
		return fmt.Errorf("caddy: %s cannot be empty", label)
	}
	if strings.ContainsAny(value, "\x00\r\n;&|`$<>{}[]*?") {
		return fmt.Errorf("caddy: %s %q contains shell metacharacters", label, value)
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("caddy: %s %q contains whitespace; configure argv tokens explicitly", label, value)
		}
	}
	return nil
}

func shellName(command string) bool {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}
