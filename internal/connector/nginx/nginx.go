// Package nginx is the NGINX deployment connector (S5.6), built from the
// connector SDK (S5.5). It installs a renewed certificate the way an operator
// would: write the certificate and key to the paths nginx.conf references,
// validate the configuration with `nginx -t`, then reload. Because nginx keeps
// serving the running certificate until a successful reload, a certificate that
// fails validation never takes effect.
package nginx

import (
	"context"
	"fmt"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector deploys certificates to an NGINX host.
type Connector struct {
	certPath string
	keyPath  string
	binary   string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithBinary sets the nginx binary to invoke (default "nginx") — for example an
// absolute path, or "openresty".
func WithBinary(bin string) Option {
	return func(c *Connector) { c.binary = bin }
}

// New returns a connector that writes the certificate to certPath and the key to
// keyPath (the ssl_certificate / ssl_certificate_key paths in nginx.conf) and
// reloads nginx to activate them.
func New(certPath, keyPath string, opts ...Option) *Connector {
	c := &Connector{certPath: certPath, keyPath: keyPath, binary: "nginx"}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "nginx" }

// Capabilities declares the least privilege the connector needs: write under the
// certificate/key directories, and run nginx (for `-t` and `-s reload`). It
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
// reloads. If validation (`nginx -t`) fails, nginx is not reloaded and keeps
// serving the previous certificate.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := sb.WriteFile(c.certPath, dep.CertPEM); err != nil {
		return fmt.Errorf("nginx: write certificate: %w", err)
	}
	if err := sb.WriteFile(c.keyPath, dep.KeyPEM); err != nil {
		return fmt.Errorf("nginx: write key: %w", err)
	}
	if err := sb.Exec(c.binary, "-t"); err != nil {
		return fmt.Errorf("nginx: configuration test failed, not reloading: %w", err)
	}
	if err := sb.Exec(c.binary, "-s", "reload"); err != nil {
		return fmt.Errorf("nginx: reload: %w", err)
	}
	return nil
}
