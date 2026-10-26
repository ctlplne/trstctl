// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Wrapped key import (A128). An operator's existing CA private key reaches the
// isolated signer sealed to a one-time import key the signer holds, using HPKE
// (RFC 9180) base mode with the MLKEM768-P256 hybrid KEM, HKDF-SHA256 and
// AES-256-GCM: every component is FIPS-approved, and the ML-KEM half keeps a
// recorded transfer safe from a later quantum attack. The control plane relays
// only sealed bytes; the plaintext PKCS#8 exists on the operator's machine and,
// for the duration of one call, inside the signer.

// KeyImportSuite names the sealing suite in the signer's offer and the
// operator's wrap step, so a later suite is a new name, never a silent change.
const KeyImportSuite = "hpke-base-mlkem768p256-hkdfsha256-aes256gcm"

// KeyImportSeedSize is the size of an import key's seed.
const KeyImportSeedSize = 32

// MaxKeyImportPlaintext bounds a sealed private key: an RSA-4096 PKCS#8 is
// about 2.4 KiB.
const MaxKeyImportPlaintext = 16 << 10

// ErrKeyImportOpen is the single failure for a sealed key that does not open
// under the import key and binding. It carries no detail.
var ErrKeyImportOpen = errors.New("crypto: sealed key does not open under this import key and binding")

// KeyImportKey is a one-time import private key: its seed in locked memory.
type KeyImportKey struct {
	seed   *secret.Buffer
	public []byte
}

// GenerateKeyImportKey creates a fresh import key.
func GenerateKeyImportKey() (*KeyImportKey, error) {
	seed, err := RandomBytes(KeyImportSeedSize)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(seed)
	return NewKeyImportKey(seed)
}

// NewKeyImportKey rebuilds an import key from its seed. The seed is copied into
// locked memory; the caller wipes its own copy.
func NewKeyImportKey(seed []byte) (*KeyImportKey, error) {
	if len(seed) != KeyImportSeedSize {
		return nil, fmt.Errorf("crypto: import key seed must be %d bytes", KeyImportSeedSize)
	}
	private, err := hpke.MLKEM768P256().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("crypto: import key: %w", err)
	}
	buf, err := secret.NewFrom(seed)
	if err != nil {
		return nil, err
	}
	return &KeyImportKey{seed: buf, public: private.PublicKey().Bytes()}, nil
}

// Public returns the import key's public half, the bytes an operator seals to.
func (k *KeyImportKey) Public() []byte { return append([]byte(nil), k.public...) }

// Seed returns a copy of the seed for sealed persistence. The caller must seal
// it and wipe the copy.
func (k *KeyImportKey) Seed() ([]byte, error) {
	var out []byte
	err := k.seed.Use(func(seed []byte) error {
		out = append([]byte(nil), seed...)
		return nil
	})
	return out, err
}

// Destroy wipes the import key.
func (k *KeyImportKey) Destroy() { k.seed.Destroy() }

// Open opens a sealed private key bound to info. The plaintext is unprotected
// memory the caller must wipe as soon as it has moved it into locked custody.
func (k *KeyImportKey) Open(info, sealed []byte) ([]byte, error) {
	var out []byte
	err := k.seed.Use(func(seed []byte) error {
		private, err := hpke.MLKEM768P256().NewPrivateKey(seed)
		if err != nil {
			return err
		}
		plaintext, err := hpke.Open(private, hpke.HKDFSHA256(), hpke.AES256GCM(), info, sealed)
		if err != nil {
			return ErrKeyImportOpen
		}
		out = plaintext
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 || len(out) > MaxKeyImportPlaintext {
		secret.Wipe(out)
		return nil, ErrKeyImportOpen
	}
	return out, nil
}

// SealKeyImport seals a private key to an import key's public half: the
// operator's wrap step, run on the operator's machine.
func SealKeyImport(public, info, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxKeyImportPlaintext {
		return nil, fmt.Errorf("crypto: a sealed private key must be 1 to %d bytes", MaxKeyImportPlaintext)
	}
	key, err := hpke.MLKEM768P256().NewPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("crypto: import public key: %w", err)
	}
	return hpke.Seal(key, hpke.HKDFSHA256(), hpke.AES256GCM(), info, plaintext)
}

// KeyImportInfo binds a sealed key to one import: the tenant, the operation
// that requested the import key, and the public key the imported private key
// must match. A sealed key cannot be replayed into another tenant or operation,
// or swapped for a different key.
func KeyImportInfo(tenantID, operationID string, expectedSPKI []byte) []byte {
	digest := sha256.Sum256(expectedSPKI)
	return []byte("trstctl.ca-key-import.v1\x00" + tenantID + "\x00" + operationID + "\x00" + hex.EncodeToString(digest[:]))
}
