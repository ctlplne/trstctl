// Package apache is the Apache (httpd) deployment connector (S5.7), built from
// the connector SDK (S5.5). It installs a renewed certificate the way an
// operator would: write the certificate and key to the paths the
// SSLCertificateFile / SSLCertificateKeyFile directives reference, validate the
// configuration with `apachectl configtest`, then `apachectl graceful`. Because
// apache keeps serving the running certificate until a successful graceful
// reload, a certificate that fails the config test never takes effect.
package apache

import (
	"context"
	"fmt"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector deploys certificates to an Apache host.
type Connector struct {
	certPath string
	keyPath  string
	binary   string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithBinary sets the apachectl binary to invoke (default "apachectl") — for
// example "apache2ctl" on Debian/Ubuntu or an absolute path.
func WithBinary(bin string) Option {
	return func(c *Connector) { c.binary = bin }
}

// New returns a connector that writes the certificate to certPath and the key to
// keyPath (the SSLCertificateFile / SSLCertificateKeyFile paths) and gracefully
// reloads apache to activate them.
func New(certPath, keyPath string, opts ...Option) *Connector {
	c := &Connector{certPath: certPath, keyPath: keyPath, binary: "apachectl"}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "apache" }

// Capabilities declares the least privilege the connector needs: write under the
// certificate/key directories, and run apachectl (configtest and graceful). It
// never needs the network.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSWrite, connector.CapExec).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.certPath))
	if d := path.Dir(c.keyPath); d != path.Dir(c.certPath) {
		g = g.WithPathPrefix(pluginhost.CapFSWrite, d)
	}
	return g
}

// Deploy writes the renewed credential, validates the configuration, and
// gracefully reloads. If `apachectl configtest` fails, apache is not reloaded
// and keeps serving the previous certificate.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := sb.WriteFile(c.certPath, dep.CertPEM); err != nil {
		return fmt.Errorf("apache: write certificate: %w", err)
	}
	if err := sb.WriteFile(c.keyPath, dep.KeyPEM); err != nil {
		return fmt.Errorf("apache: write key: %w", err)
	}
	if err := sb.Exec(c.binary, "configtest"); err != nil {
		return fmt.Errorf("apache: configtest failed, not reloading: %w", err)
	}
	if err := sb.Exec(c.binary, "graceful"); err != nil {
		return fmt.Errorf("apache: graceful reload: %w", err)
	}
	return nil
}
