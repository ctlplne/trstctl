package signing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/seal"
	"certctl.io/certctl/internal/crypto/secret"
)

// KeyStore persists signer keys to a directory, each sealed at rest with a KEK
// (R3.2): a key survives a signer restart, so the issuing CA is not silently
// rotated. Only sealed ciphertext is written to disk; the sealing/unsealing is
// the envelope-encryption boundary (internal/crypto/seal). The signer can use
// this without importing the store (AN-4).
type KeyStore struct {
	dir     string
	wrapper seal.KeyWrapper
}

// NewKeyStore returns a KeyStore over dir, sealing with wrapper.
func NewKeyStore(dir string, wrapper seal.KeyWrapper) *KeyStore {
	return &KeyStore{dir: dir, wrapper: wrapper}
}

const keyFileExt = ".key"

func (ks *KeyStore) path(stem string) string {
	return filepath.Join(ks.dir, stem+keyFileExt)
}

// Save seals the key's PKCS#8 material (bound to the handle as AAD) and writes it
// 0600. The unsealed key copy lives only for the moment of sealing, then is wiped.
func (ks *KeyStore) Save(handle string, ls *crypto.LockedSigner) error {
	stem := sanitizeHandle(handle)
	der, err := ls.PKCS8()
	if err != nil {
		return err
	}
	defer secret.Wipe(der)
	sealed, err := seal.Seal(ks.wrapper, der, []byte(stem))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(ks.path(stem), sealed, 0o600)
}

// Load reads and unseals every persisted key into a handle->LockedSigner map. A
// missing directory is an empty store (first boot), not an error.
func (ks *KeyStore) Load() (map[string]*crypto.LockedSigner, error) {
	out := map[string]*crypto.LockedSigner{}
	entries, err := os.ReadDir(ks.dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, keyFileExt) {
			continue
		}
		stem := strings.TrimSuffix(name, keyFileExt)
		sealed, err := os.ReadFile(filepath.Join(ks.dir, name))
		if err != nil {
			return nil, err
		}
		der, err := seal.Open(ks.wrapper, sealed, []byte(stem))
		if err != nil {
			return nil, fmt.Errorf("signing: open sealed key %q: %w", stem, err)
		}
		ls, err := crypto.LockedKeyFromPKCS8(der)
		secret.Wipe(der)
		if err != nil {
			return nil, fmt.Errorf("signing: load key %q: %w", stem, err)
		}
		out[stem] = ls
	}
	return out, nil
}

// Remove deletes a persisted key. A missing file is not an error.
func (ks *KeyStore) Remove(handle string) error {
	err := os.Remove(ks.path(sanitizeHandle(handle)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// sanitizeHandle restricts a handle to a safe filename charset. Real handles are
// hex ids or fixed names like "issuing-ca", so this is identity for them.
func sanitizeHandle(h string) string {
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
