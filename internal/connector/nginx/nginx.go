// SPDX-License-Identifier: BUSL-1.1

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

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// ReexecAction is the host action that activates a TPM-held key
// (TPM-O1-L3): nginx is re-executed, the binary upgrade nginx documents (the
// running master starts a new master, which loads the configuration and the
// key in a fresh process; the old one finishes its connections and exits),
// instead of being reloaded in place. With OpenSSL 3's tpm2 provider an
// in-place reload leaves nginx failing every TLS handshake or still serving
// the previous certificate. The operator's host profile maps it, for example
// to Debian's `/etc/init.d/nginx upgrade`.
const ReexecAction = "nginx-upgrade"

// Connector deploys certificates to an NGINX host.
type Connector struct {
	certPath string
	keyPath  string
	binary   string
	reexec   bool
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithBinary sets the nginx binary to invoke (default "nginx") — for example an
// absolute path, or "openresty".
func WithBinary(bin string) Option {
	return func(c *Connector) { c.binary = bin }
}

// WithReexec activates a deploy with the host profile's ReexecAction instead
// of `nginx -s reload`: the agent asks for it when the key is TPM-held.
func WithReexec() Option {
	return func(c *Connector) { c.reexec = true }
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
// certificate/key directories, and run nginx (for `-t` and `-s reload`, or the
// re-exec action). It never needs the network.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSWrite, connector.CapExec).
		WithPathPrefix(pluginhost.CapFSWrite, connector.TargetDir(c.certPath))
	if d := connector.TargetDir(c.keyPath); d != connector.TargetDir(c.certPath) {
		g = g.WithPathPrefix(pluginhost.CapFSWrite, d)
	}
	return g
}

// Deploy writes the renewed credential, validates the configuration, and
// reloads (or, WithReexec, re-executes nginx). If validation (`nginx -t`)
// fails, nginx is not reloaded and keeps serving the previous certificate.
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
	if c.reexec {
		if err := sb.Exec(ReexecAction); err != nil {
			return fmt.Errorf("nginx: re-execute: %w", err)
		}
		return nil
	}
	if err := sb.Exec(c.binary, "-s", "reload"); err != nil {
		return fmt.Errorf("nginx: reload: %w", err)
	}
	return nil
}
