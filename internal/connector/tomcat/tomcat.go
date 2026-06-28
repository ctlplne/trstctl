// Package tomcat deploys renewed PEM TLS files to an Apache Tomcat connector
// and invokes a direct reload command.
package tomcat

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Connector writes Tomcat TLS certificate and key files.
type Connector struct {
	certPath string
	keyPath  string
	reload   []string
}

var _ connector.Connector = (*Connector)(nil)

// New returns a Tomcat connector for the configured PEM cert and key.
func New(certPath, keyPath string) *Connector {
	return &Connector{certPath: certPath, keyPath: keyPath, reload: []string{"catalina.sh", "reload"}}
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
	return deployFiles("tomcat", c.certPath, c.keyPath, c.reload, sb, dep)
}

func deployFiles(prefix, certPath, keyPath string, reload []string, sb connector.Sandbox, dep connector.Deployment) error {
	oldCert, hadCert, err := readExisting(sb, certPath)
	if err != nil {
		return fmt.Errorf("%s: read current certificate: %w", prefix, err)
	}
	oldKey, hadKey, err := readExisting(sb, keyPath)
	if err != nil {
		return fmt.Errorf("%s: read current key: %w", prefix, err)
	}
	if hadCert && crypto.SHA256Hex(oldCert) == dep.Fingerprint && (len(dep.KeyPEM) == 0 || hadKey && bytes.Equal(oldKey, dep.KeyPEM)) {
		return nil
	}
	if err := sb.WriteFile(certPath, dep.CertPEM); err != nil {
		return fmt.Errorf("%s: write certificate: %w", prefix, err)
	}
	if len(dep.KeyPEM) > 0 {
		if err := sb.WriteFile(keyPath, dep.KeyPEM); err != nil {
			_ = rollback(sb, certPath, oldCert, hadCert, keyPath, oldKey, hadKey)
			return fmt.Errorf("%s: write key: %w", prefix, err)
		}
	}
	if len(reload) > 0 {
		if err := sb.Exec(reload[0], reload[1:]...); err != nil {
			if rb := rollback(sb, certPath, oldCert, hadCert, keyPath, oldKey, hadKey); rb != nil {
				return fmt.Errorf("%s: reload failed and rollback failed: reload=%w rollback=%v", prefix, err, rb)
			}
			return fmt.Errorf("%s: reload failed; rollback complete: %w", prefix, err)
		}
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
	if hadCert {
		if err := sb.WriteFile(certPath, oldCert); err != nil {
			return fmt.Errorf("restore certificate: %w", err)
		}
	}
	if hadKey {
		if err := sb.WriteFile(keyPath, oldKey); err != nil {
			return fmt.Errorf("restore key: %w", err)
		}
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
