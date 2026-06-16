// Package haproxy is the HAProxy deployment connector (S5.9), built from the
// connector SDK (S5.5). HAProxy reads the certificate and key from a single
// combined PEM file (the `ssl crt` file: certificate chain followed by the
// private key). The connector writes that combined file, validates the
// configuration with `haproxy -c`, then reloads. Because haproxy keeps serving
// the running bundle until a successful reload, a bundle that fails the config
// check never takes effect.
package haproxy

import (
	"context"
	"fmt"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector deploys certificates to an HAProxy host.
type Connector struct {
	crtPath    string // the combined cert+key PEM file (the `ssl crt` path)
	configPath string // haproxy.cfg, validated with `haproxy -c -f`
	binary     string
	reloadCmd  []string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithBinary sets the haproxy binary to invoke (default "haproxy").
func WithBinary(bin string) Option { return func(c *Connector) { c.binary = bin } }

// WithReloadCommand sets the command (name and args) used to reload haproxy
// (default "systemctl reload haproxy").
func WithReloadCommand(cmd ...string) Option {
	return func(c *Connector) { c.reloadCmd = cmd }
}

// New returns a connector that writes the combined certificate+key to crtPath
// (the `ssl crt` path) and reloads haproxy to activate it. configPath is the
// haproxy.cfg passed to `haproxy -c`.
func New(crtPath, configPath string, opts ...Option) *Connector {
	c := &Connector{
		crtPath: crtPath, configPath: configPath, binary: "haproxy",
		reloadCmd: []string{"systemctl", "reload", "haproxy"},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "haproxy" }

// Capabilities declares the least privilege the connector needs: write under the
// certificate directory, and run haproxy (the config check) and the reload
// command. It never needs the network.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapFSWrite, connector.CapExec).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.crtPath))
}

// Deploy writes the combined certificate+key bundle, validates the
// configuration, and reloads. If `haproxy -c` fails, haproxy is not reloaded and
// keeps serving the previous bundle.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	bundle := combine(dep.CertPEM, dep.KeyPEM)
	if err := sb.WriteFile(c.crtPath, bundle); err != nil {
		return fmt.Errorf("haproxy: write certificate bundle: %w", err)
	}
	if err := sb.Exec(c.binary, "-c", "-f", c.configPath); err != nil {
		return fmt.Errorf("haproxy: configuration check failed, not reloading: %w", err)
	}
	if len(c.reloadCmd) > 0 {
		if err := sb.Exec(c.reloadCmd[0], c.reloadCmd[1:]...); err != nil {
			return fmt.Errorf("haproxy: reload: %w", err)
		}
	}
	return nil
}

// combine concatenates the certificate chain and the key into the single PEM
// file HAProxy expects (certificate first, then key), ensuring a newline
// separates them.
func combine(certPEM, keyPEM []byte) []byte {
	out := make([]byte, 0, len(certPEM)+len(keyPEM)+1)
	out = append(out, certPEM...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, keyPEM...)
	return out
}
