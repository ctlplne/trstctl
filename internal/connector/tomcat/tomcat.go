// SPDX-License-Identifier: MPL-2.0

// Package tomcat deploys renewed TLS files to a Tomcat server and runs a direct
// reload command so the listener can use the new certificate.
package tomcat

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector writes Tomcat TLS certificate and key files.
type Connector struct {
	certPath string
	keyPath  string
}

// TLSReloadAction is the fixed operator-owned action that activates Tomcat's
// TLS context. Map it to the shipped agent's one-shot Tomcat Manager client
// with an exact SSLHostConfig name and a private password file. Stock
// catalina.sh has no TLS reload command.
const TLSReloadAction = "tomcat-tls-reload"

var _ connector.Connector = (*Connector)(nil)

// New returns a Tomcat connector for the configured server cert and key.
func New(certPath, keyPath string) *Connector {
	return &Connector{certPath: certPath, keyPath: keyPath}
}

// Name identifies the connector.
func (c *Connector) Name() string { return "tomcat" }

// Capabilities grants read/write on configured TLS directories and process exec
// for the direct reload command.
func (c *Connector) Capabilities() pluginhost.Grant {
	return fileGrant(c.certPath, c.keyPath, true)
}

// Deploy writes the renewed certificate/key and reloads Tomcat.
func (c *Connector) Deploy(_ context.Context, sb connector.Sandbox, dep connector.Deployment) error {
	return deployFiles("tomcat", c.certPath, c.keyPath, sb, dep)
}

func deployFiles(prefix, certPath, keyPath string, sb connector.Sandbox, dep connector.Deployment) error {
	oldCert, hadCert, err := readExisting(sb, certPath)
	if err != nil {
		return fmt.Errorf("%s: read current certificate: %w", prefix, err)
	}
	defer secret.Wipe(oldCert)
	oldKey, hadKey, err := readExisting(sb, keyPath)
	if err != nil {
		return fmt.Errorf("%s: read current key: %w", prefix, err)
	}
	defer secret.Wipe(oldKey)
	// Repeating identical file bytes must still activate TLS: an earlier
	// attempt may have stopped between the file write and the server reload.
	if err := sb.WriteFile(certPath, dep.CertPEM); err != nil {
		return fmt.Errorf("%s: write certificate: %w", prefix, err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := sb.WriteFile(keyPath, dep.KeyPEM); err != nil {
			if rb := rollback(sb, certPath, oldCert, hadCert, keyPath, oldKey, hadKey); rb != nil {
				return fmt.Errorf("%s: write key failed and predecessor restore failed: write=%w restore=%v", prefix, err, rb)
			}
			return fmt.Errorf("%s: write key failed; predecessor files restored: %w", prefix, err)
		}
	}
	if err := sb.Exec(TLSReloadAction); err != nil {
		if rb := rollback(sb, certPath, oldCert, hadCert, keyPath, oldKey, hadKey); rb != nil {
			return fmt.Errorf("%s: TLS reload failed and predecessor restore failed: reload=%w restore=%v", prefix, err, rb)
		}
		if rb := sb.Exec(TLSReloadAction); rb != nil {
			return fmt.Errorf("%s: TLS reload failed; predecessor files restored but its TLS activation failed: reload=%w restore=%v", prefix, err, rb)
		}
		return fmt.Errorf("%s: TLS reload failed; predecessor files restored and TLS reload completed: %w", prefix, err)
	}
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

func rollback(sb connector.Sandbox, certPath string, oldCert []byte, hadCert bool, keyPath string, oldKey []byte, hadKey bool) error {
	if !hadCert || !hadKey {
		return errors.New("no complete predecessor certificate/key pair exists to restore")
	}
	if err := sb.WriteFile(certPath, oldCert); err != nil {
		return fmt.Errorf("restore certificate: %w", err)
	}
	if err := sb.WriteFile(keyPath, oldKey); err != nil {
		return fmt.Errorf("restore key: %w", err)
	}
	return nil
}

func fileGrant(certPath, keyPath string, exec bool) pluginhost.Grant {
	caps := []pluginhost.Capability{pluginhost.CapFSRead, pluginhost.CapFSWrite}
	if exec {
		caps = append(caps, connector.CapExec)
	}
	g := pluginhost.NewGrant(caps...).
		WithPathPrefix(pluginhost.CapFSRead, path.Dir(certPath)).
		WithPathPrefix(pluginhost.CapFSWrite, path.Dir(certPath))
	if d := path.Dir(keyPath); d != path.Dir(certPath) {
		g = g.WithPathPrefix(pluginhost.CapFSRead, d).WithPathPrefix(pluginhost.CapFSWrite, d)
	}
	return g
}
