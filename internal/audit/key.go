package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"certctl.io/certctl/internal/crypto/jose"
)

// LoadOrCreateSigningKey returns the audit export signing key, persisted at path
// so it does not rotate across restarts (R2.1 / B5): if the file already exists
// it is loaded; otherwise a fresh key is generated and written with owner-only
// (0600) permissions. Because the same key is reloaded on the next boot, an
// evidence bundle signed before a restart still verifies after one. Key
// generation and parsing route through the crypto boundary (internal/crypto/jose,
// AN-3); only the file I/O lives here.
func LoadOrCreateSigningKey(path, kid string) (*jose.SigningKey, error) {
	if path == "" {
		return nil, errors.New("audit: signing key path is required to persist the export key")
	}
	switch data, err := os.ReadFile(path); {
	case err == nil:
		return jose.ParseRSASigningKey(kid, data)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("audit: read signing key %q: %w", path, err)
	}

	key, err := jose.GenerateRSASigningKey(kid)
	if err != nil {
		return nil, err
	}
	pemBytes, err := key.MarshalPrivateKey()
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: create signing key directory: %w", err)
		}
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("audit: write signing key %q: %w", path, err)
	}
	return key, nil
}
