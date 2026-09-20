// SPDX-License-Identifier: BUSL-1.1

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
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
)

// defaultAppID is the HTTP.SYS application id IIS uses for its SSL bindings.
const defaultAppID = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"

// defaultImportDir is the scoped transient-file directory used to pass PFX bytes
// and the random import password to PowerShell without embedding either secret in
// process arguments.
const defaultImportDir = "C:/ProgramData/trstctl/iis-import"

// Connector deploys certificates to an IIS host.
type Connector struct {
	binding    string // the HTTPS binding, "ip:port" (for example "0.0.0.0:443")
	store      string // certificate store name (default "MY")
	appID      string
	importDir  string
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

// WithImportDir sets the scoped directory used for transient PFX/password files.
func WithImportDir(dir string) Option {
	return func(c *Connector) {
		if dir != "" {
			c.importDir = cleanImportDir(dir)
		}
	}
}

// New returns a connector that binds the certificate to the HTTPS binding
// "ip:port".
func New(binding string, opts ...Option) *Connector {
	c := &Connector{
		binding:    binding,
		store:      "MY",
		appID:      defaultAppID,
		importDir:  defaultImportDir,
		powershell: "powershell",
		netsh:      "netsh",
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the connector.
func (c *Connector) Name() string { return "iis" }

// Capabilities declares the least privilege the connector needs: run commands
// (the certificate import and `netsh`) and write only the scoped transient import
// files used to keep PFX/password bytes out of process arguments. It never uses
// the network.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(connector.CapExec, pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, c.importDir+"/")
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
	defer secret.Wipe(pfxDER)
	defer secret.Wipe(password)

	pfxPath, passwordPath := c.importPaths(dep.Fingerprint)
	cleanupStaged := false
	defer func() {
		if cleanupStaged {
			_ = sb.WriteFile(pfxPath, nil)
			_ = sb.WriteFile(passwordPath, nil)
		}
	}()
	if err := sb.WriteFile(pfxPath, pfxDER); err != nil {
		return fmt.Errorf("iis: stage PFX: %w", err)
	}
	cleanupStaged = true
	if err := sb.WriteFile(passwordPath, password); err != nil {
		return fmt.Errorf("iis: stage PFX password: %w", err)
	}
	if err := sb.Exec(c.powershell, "-NoProfile", "-NonInteractive", "-Command", importCommand(pfxPath, passwordPath, c.store)); err != nil {
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

func (c *Connector) importPaths(fingerprint string) (pfxPath, passwordPath string) {
	stem := fingerprint
	if stem == "" {
		stem = "deployment"
	}
	return c.importDir + "/" + stem + ".pfx", c.importDir + "/" + stem + ".pw"
}

// importCommand builds the PowerShell command that adds the staged PFX to the
// LocalMachine\<store> store. The command carries only paths and store names; the
// PFX bytes and transient password are read from files and removed in finally.
func importCommand(pfxPath, passwordPath, store string) string {
	return fmt.Sprintf(
		"$pfx=%s; $pwPath=%s; "+
			"try { "+
			"$pw=Get-Content -LiteralPath $pwPath -Raw; "+
			"$sec=ConvertTo-SecureString -String $pw -AsPlainText -Force; "+
			"Import-PfxCertificate -FilePath $pfx -CertStoreLocation %s -Password $sec | Out-Null "+
			"} finally { "+
			"Remove-Item -LiteralPath $pfx,$pwPath -Force -ErrorAction SilentlyContinue "+
			"}",
		psQuote(pfxPath), psQuote(passwordPath), psQuote("Cert:\\LocalMachine\\"+store))
}

func cleanImportDir(dir string) string {
	dir = strings.TrimRight(dir, `/\`)
	if dir == "" {
		return defaultImportDir
	}
	return dir
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
