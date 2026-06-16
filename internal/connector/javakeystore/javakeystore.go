// Package javakeystore is the Java keystore deployment connector (S5.13.2), built
// from the connector SDK (S5.5). Unlike the appliance and cloud connectors, a
// Java keystore is a file the agent writes to the host filesystem — so, like the
// NGINX/Apache/HAProxy connectors, it deploys through sb.WriteFile (capability
// fs.write), never the network or a command.
//
// It supports both formats Java applications use: PKCS#12 (the modern Java
// default) and JKS (the legacy 0xFEEDFEED format). The keystore is built through
// the crypto boundary (internal/crypto/pfx and internal/crypto/jks), so the
// connector itself imports no crypto/* (AN-3); key material is carried as []byte
// (AN-8). Encoding is deterministic (the salts are derived from the credential),
// so redelivering the same renewal rewrites byte-identical bytes — the
// deployment is idempotent (AN-5/AN-6).
//
// The entry alias and store password are connector configuration; the alias is
// authoritative for JKS, while a single-entry PKCS#12 uses the encoder's default
// friendly name.
package javakeystore

import (
	"context"
	"fmt"
	"path"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Format is a keystore container format.
type Format string

const (
	// FormatPKCS12 is the modern Java keystore format (.p12 / .pfx).
	FormatPKCS12 Format = "pkcs12"
	// FormatJKS is the legacy Java KeyStore format (.jks).
	FormatJKS Format = "jks"
)

// Connector writes a renewed credential into a Java keystore file.
type Connector struct {
	keystorePath string
	password     string
	alias        string
	format       Format
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithFormat overrides the keystore format (otherwise inferred from the file
// extension: .jks is JKS, everything else PKCS#12).
func WithFormat(f Format) Option {
	return func(c *Connector) {
		if f != "" {
			c.format = f
		}
	}
}

// New returns a connector that writes the renewed credential into the keystore
// at keystorePath, under alias, protected by password. The format is inferred
// from the file extension unless WithFormat is given.
func New(keystorePath, password, alias string, opts ...Option) *Connector {
	c := &Connector{
		keystorePath: keystorePath,
		password:     password,
		alias:        alias,
		format:       inferFormat(keystorePath),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func inferFormat(p string) Format {
	if strings.EqualFold(path.Ext(p), ".jks") {
		return FormatJKS
	}
	return FormatPKCS12
}

// Name identifies the connector.
func (c *Connector) Name() string { return "java-keystore" }

// Capabilities declares the least privilege the connector needs: write the
// keystore file. No network, no exec.
func (c *Connector) Capabilities() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.keystorePath))
}

// Deploy encodes the renewed key and certificate chain into the configured
// keystore format and writes it to the keystore path.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	var blob []byte
	var err error
	switch c.format {
	case FormatJKS:
		blob, err = jks.EncodeDeterministic(dep.KeyPEM, dep.CertPEM, c.password, c.alias)
	default:
		blob, err = pfx.EncodeDeterministic(dep.KeyPEM, dep.CertPEM, c.password)
	}
	if err != nil {
		return fmt.Errorf("java-keystore: encode %s: %w", c.format, err)
	}
	if err := sb.WriteFile(c.keystorePath, blob); err != nil {
		return fmt.Errorf("java-keystore: write keystore: %w", err)
	}
	return nil
}
