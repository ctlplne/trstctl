// Package example is a sample deployment connector built from the connector SDK
// (S5.5). It is the model every real connector (S5.6+) follows: implement the
// Connector seam and declare the capabilities it needs — nothing more.
//
// This connector represents the file-plus-reload shape (NGINX, Apache, HAProxy):
// it writes the certificate and key into a directory and runs a reload command.
// It therefore needs exactly two capabilities — write under its directory, and
// exec the reload — and the sandbox denies anything else.
package example

import (
	"context"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector writes a credential to a directory and reloads a service.
type Connector struct {
	dir    string
	reload []string
}

var _ connector.Connector = (*Connector)(nil)

// New returns a connector that installs into dir and runs reloadCmd (name and
// args) to activate the new credential.
func New(dir string, reloadCmd ...string) *Connector {
	return &Connector{dir: dir, reload: reloadCmd}
}

// Name identifies the connector.
func (c *Connector) Name() string { return "filereload" }

// Capabilities declares exactly what the connector needs: write under its
// directory, and exec the reload command.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapFSWrite, connector.CapExec).
		WithPathPrefix(pluginhost.CapFSWrite, c.dir)
}

// Deploy writes the certificate and key and reloads the service, all through
// the capability-gated sandbox.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := sb.WriteFile(path.Join(c.dir, "tls.crt"), dep.CertPEM); err != nil {
		return err
	}
	if err := sb.WriteFile(path.Join(c.dir, "tls.key"), dep.KeyPEM); err != nil {
		return err
	}
	if len(c.reload) > 0 {
		return sb.Exec(c.reload[0], c.reload[1:]...)
	}
	return nil
}
