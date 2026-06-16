// Package kek loads or creates the key-encryption key (KEK) used for envelope
// encryption (R3.1/R3.2). It lives under the crypto boundary and depends only on
// internal/crypto/seal — deliberately NOT on internal/secrets (which imports the
// store), so the out-of-process signer can load a KEK without linking a SQL
// driver (AN-4).
package kek

import (
	"errors"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// LoadOrCreate loads a 32-byte KEK from path, creating one (random, written
// 0600) if the file does not exist.
func LoadOrCreate(path string) (*seal.LocalKEK, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		defer secret.Wipe(raw)
		return seal.NewLocalKEK(raw)
	case errors.Is(err, os.ErrNotExist):
		fresh, err := seal.GenerateKEK()
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(fresh)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, fresh, 0o600); err != nil {
			return nil, err
		}
		return seal.NewLocalKEK(fresh)
	default:
		return nil, err
	}
}
