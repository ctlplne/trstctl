package destination

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File and directory modes for the filesystem destination. The private key is
// owner-only; the certificate is world-readable; the directories that hold them
// are private so a key is never momentarily exposed via a loose parent.
const (
	certFileMode = 0o644
	keyFileMode  = 0o600
	dirMode      = 0o700
)

// Filesystem installs a credential as PEM files on local disk. The certificate
// is written world-readable and the key owner-only; both parent directories are
// created private. The final permissions are set explicitly (independent of the
// process umask or any pre-existing file mode), so a key is never left more
// permissive than 0600.
type Filesystem struct {
	certPath string
	keyPath  string
}

var _ Destination = (*Filesystem)(nil)

// NewFilesystem returns a filesystem destination that writes the certificate to
// certPath and, when the credential carries one, the key to keyPath.
func NewFilesystem(certPath, keyPath string) *Filesystem {
	return &Filesystem{certPath: certPath, keyPath: keyPath}
}

// Install writes the certificate (and key, if present) with correct permissions.
func (f *Filesystem) Install(_ context.Context, cred Credential) error {
	if len(cred.CertPEM) == 0 {
		return errors.New("destination: nothing to install (empty certificate)")
	}
	// Write the key first: until the certificate is in place the credential is
	// not yet usable, and the key is the sensitive half.
	if cred.HasKey() {
		if err := writeRestricted(f.keyPath, cred.KeyPEM, keyFileMode); err != nil {
			return fmt.Errorf("destination: write key: %w", err)
		}
	}
	if err := writeRestricted(f.certPath, cred.CertPEM, certFileMode); err != nil {
		return fmt.Errorf("destination: write certificate: %w", err)
	}
	return nil
}

// Describe returns a short identifier for the destination.
func (f *Filesystem) Describe() string { return "filesystem(" + f.certPath + ")" }

// writeRestricted writes data to path, creating the parent directory private
// (0700) and forcing path to exactly mode regardless of umask or any
// pre-existing, looser permissions on the file.
func writeRestricted(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	// MkdirAll honors umask; force the leaf directory to exactly dirMode.
	if err := os.Chmod(dir, dirMode); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	// WriteFile does not change the mode of an existing file and is subject to
	// umask for a new one; set the exact mode unconditionally.
	return os.Chmod(path, mode)
}
