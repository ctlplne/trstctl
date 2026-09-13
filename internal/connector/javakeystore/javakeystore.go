// SPDX-License-Identifier: MPL-2.0

// Package javakeystore is the Java keystore deployment connector (S5.13.2), built
// from the connector SDK (S5.5). Unlike the appliance and cloud connectors, a
// Java keystore is a file the agent writes to the host filesystem — so, like the
// NGINX/Apache/HAProxy connectors, it deploys through sb.WriteFile (capability
// fs.write). An optional named host action reloads the consuming application.
//
// It supports both formats Java applications use: PKCS#12 (the modern Java
// default) and JKS (the legacy 0xFEEDFEED format). The keystore is built through
// the crypto boundary (internal/crypto/pfx and internal/crypto/jks), so the
// connector itself imports no crypto/* (AN-3); key material is carried as []byte
// (AN-8). Encoding is deterministic (the salts are derived from the credential),
// so redelivering the same renewal rewrites byte-identical bytes — the
// deployment is idempotent (AN-5/AN-6).
//
// The entry alias and store password are connector configuration. Both formats
// preserve the configured alias, including Java's PKCS#12 key friendlyName.
package javakeystore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	password     []byte
	alias        string
	format       Format
	reloadAction string
}

var _ connector.Connector = (*Connector)(nil)

// Option configures a Connector.
type Option func(*Connector)

// WithReloadAction selects one logical action from the operator-owned host
// profile. No executable, arguments, environment or password comes from the
// target. Without it the connector only writes a keystore.
func WithReloadAction(name string) Option {
	return func(c *Connector) { c.reloadAction = name }
}

// ValidateReloadAction accepts an optional, bounded host-profile label.
func ValidateReloadAction(name string) error {
	if len(name) > 64 {
		return errors.New("java-keystore: reload_action must be at most 64 characters")
	}
	for _, r := range name {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.'
		if !valid {
			return errors.New("java-keystore: reload_action must be a host action name using letters, digits, dot, underscore or hyphen")
		}
	}
	return nil
}

// Validate checks deployment inputs before a host generates or signs a key.
func (c *Connector) Validate() error {
	if err := ValidateReloadAction(c.reloadAction); err != nil {
		return err
	}
	if c.format != FormatPKCS12 && c.format != FormatJKS {
		return errors.New("java-keystore: format must be pkcs12 or jks")
	}
	if c.format == FormatPKCS12 {
		if err := pfx.ValidateJavaAlias(c.alias); err != nil {
			return err
		}
		for _, b := range c.password {
			if b < 0x20 || b > 0x7e {
				return errors.New("java-keystore: PKCS12 requires a printable ASCII store password for stock Java compatibility; use a randomly generated ASCII password")
			}
		}
	}
	return nil
}

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
func New(keystorePath string, password []byte, alias string, opts ...Option) *Connector {
	c := &Connector{
		keystorePath: keystorePath,
		password:     append([]byte(nil), password...),
		alias:        alias,
		format:       inferFormat(keystorePath),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Close destroys the keystore password copy owned by this one-shot connector.
func (c *Connector) Close() {
	secret.Wipe(c.password)
	c.password = nil
}

func inferFormat(p string) Format {
	if strings.EqualFold(path.Ext(p), ".jks") {
		return FormatJKS
	}
	return FormatPKCS12
}

// Name identifies the connector.
func (c *Connector) Name() string { return "java-keystore" }

// Capabilities declares only file writes unless an explicit reload action is
// selected. Reload also needs read access to preserve a predecessor on failure.
func (c *Connector) Capabilities() pluginhost.Grant {
	g := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.keystorePath))
	if c.reloadAction != "" {
		g = pluginhost.NewGrant(pluginhost.CapFSWrite, pluginhost.CapFSRead, connector.CapExec).
			WithPathPrefix(pluginhost.CapFSWrite, path.Dir(c.keystorePath)).
			WithPathPrefix(pluginhost.CapFSRead, path.Dir(c.keystorePath))
	}
	return g
}

// Deploy encodes the renewed key and certificate chain into the configured
// keystore format and writes it to the keystore path.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var blob []byte
	var err error
	switch c.format {
	case FormatJKS:
		blob, err = jks.EncodeDeterministicBytes(dep.KeyPEM, dep.CertPEM, c.password, c.alias)
	default:
		blob, err = pfx.EncodeDeterministicAliasBytes(dep.KeyPEM, dep.CertPEM, c.password, c.alias)
	}
	if err != nil {
		return fmt.Errorf("java-keystore: encode %s: %w", c.format, err)
	}
	defer secret.Wipe(blob)
	var previous []byte
	if c.reloadAction != "" {
		previous, err = sb.ReadFile(c.keystorePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("java-keystore: read predecessor before reload: %w", err)
		}
		defer secret.Wipe(previous)
	}
	if err := sb.WriteFile(c.keystorePath, blob); err != nil {
		return fmt.Errorf("java-keystore: write keystore: %w", err)
	}
	if c.reloadAction != "" {
		// Retry the activation even for identical file bytes: the previous
		// attempt may have written successfully but failed before reloading.
		if err := sb.Exec(c.reloadAction); err != nil {
			if previous == nil {
				return fmt.Errorf("java-keystore: reload failed; no predecessor file exists to restore: %w", err)
			}
			if restoreErr := sb.WriteFile(c.keystorePath, previous); restoreErr != nil {
				return fmt.Errorf("java-keystore: reload failed and predecessor restore failed: reload=%w restore=%v", err, restoreErr)
			}
			if restoreErr := sb.Exec(c.reloadAction); restoreErr != nil {
				return fmt.Errorf("java-keystore: reload failed; predecessor file restored but its activation failed: reload=%w restore=%v", err, restoreErr)
			}
			return fmt.Errorf("java-keystore: reload failed; predecessor file restored and reload completed: %w", err)
		}
	}
	return nil
}
