// Package kek loads or creates the key-encryption key (KEK) used for envelope
// encryption (R3.1/R3.2). It lives under the crypto boundary and depends only on
// internal/crypto/seal — deliberately NOT on internal/secrets (which imports the
// store), so the out-of-process signer can load a KEK without linking a SQL
// driver (AN-4).
package kek

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// LoadOrCreate loads a 32-byte KEK from path, creating one (random, written
// 0600) if the file does not exist.
func LoadOrCreate(path string) (*seal.LocalKEK, error) {
	raw, err := secretfile.LoadOrCreate(path, seal.GenerateKEK)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		return nil, fmt.Errorf("kek: load local KEK: %w", err)
	}
	return k, nil
}
