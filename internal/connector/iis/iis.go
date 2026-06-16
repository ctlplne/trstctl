// Package iis is the Microsoft IIS deployment connector (S5.8), built from the
// connector SDK (S5.5). Unlike the file-plus-reload connectors, IIS reads its
// certificate from the Windows certificate store and binds it to an HTTPS site
// by thumbprint. The connector therefore: computes the certificate thumbprint,
// imports the certificate (as a PFX) into the machine store, and binds the
// thumbprint to the site's HTTPS binding with `netsh http`. It runs only
// commands — no filesystem, no network.
package iis

import (
	"context"
	"encoding/base64"
	"fmt"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/pluginhost"
)

// defaultAppID is the HTTP.SYS application id IIS uses for its SSL bindings.
const defaultAppID = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"

// Connector deploys certificates to an IIS host.
type Connector struct {
	binding    string // the HTTPS binding, "ip:port" (for example "0.0.0.0:443")
	store      string // certificate store name (default "MY")
	appID      string
	powershell string
	netsh      string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithStore sets the certificate store name (default "MY").
func WithStore(name string) Option { return func(c *Connector) { c.store = name } }

// WithAppID sets the HTTP.SYS application id for the binding.
func WithAppID(id string) Option { return func(c *Connector) { c.appID = id } }

// New returns a connector that binds the certificate to the HTTPS binding
// "ip:port".
func New(binding string, opts ...Option) *Connector {
	c := &Connector{binding: binding, store: "MY", appID: defaultAppID, powershell: "powershell", netsh: "netsh"}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "iis" }

// Capabilities declares the least privilege the connector needs: run commands
// (the certificate import and `netsh`). It never writes files or uses the
// network — the certificate is delivered through the import command.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(connector.CapExec)
}

// Deploy imports the renewed certificate into the machine store and binds its
// thumbprint to the site. A malformed certificate is rejected (when computing
// the thumbprint or building the PFX) before anything is imported or bound.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	thumb, err := certinfo.Thumbprint(dep.CertPEM)
	if err != nil {
		return fmt.Errorf("iis: %w", err)
	}
	pfxDER, password, err := pfx.EncodeTransient(dep.KeyPEM, dep.CertPEM)
	if err != nil {
		return fmt.Errorf("iis: build PFX: %w", err)
	}

	if err := sb.Exec(c.powershell, "-Command", importCommand(pfxDER, password, c.store)); err != nil {
		return fmt.Errorf("iis: import certificate: %w", err)
	}

	// Rebind idempotently: remove any existing binding (best effort — it may not
	// exist), then add the new one.
	_ = sb.Exec(c.netsh, "http", "delete", "sslcert", "ipport="+c.binding)
	if err := sb.Exec(c.netsh, "http", "add", "sslcert",
		"ipport="+c.binding, "certhash="+thumb, "appid="+c.appID, "certstorename="+c.store); err != nil {
		return fmt.Errorf("iis: bind certificate: %w", err)
	}
	return nil
}

// importCommand builds the PowerShell command that adds the PFX to the
// LocalMachine\<store> store without writing a temporary file (it constructs an
// X509Certificate2 from the PFX bytes and adds it to the store).
func importCommand(pfxDER []byte, password, store string) string {
	b64 := base64.StdEncoding.EncodeToString(pfxDER)
	return fmt.Sprintf(
		"$b=[Convert]::FromBase64String('%s'); "+
			"$c=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b,'%s','MachineKeySet,PersistKeySet'); "+
			"$s=[System.Security.Cryptography.X509Certificates.X509Store]::new('%s','LocalMachine'); "+
			"$s.Open('ReadWrite'); $s.Add($c); $s.Close()",
		b64, password, store)
}
