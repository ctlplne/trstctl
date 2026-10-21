// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// KEM-wrapped data keys (PCAS data re-wrap, A16).
//
// A data key (DEK) that protects tenant data somewhere outside trstctl is
// registered with the control plane as an envelope: a KEM ciphertext made for
// the identity epoch's public encapsulation key, and the DEK sealed with
// AES-256-GCM under a key derived from the KEM shared secret and the
// envelope's binding (identity, epoch, target reference). Only the isolated
// signer, which holds the KEM private keys, can open an envelope; the control
// plane stores and moves ciphertext. These helpers are shared by the signer
// custody (re-wrap and readback), the CLI envelope helper and tests, and they
// stay inside the AN-3 boundary.

const kemDataKeyDomain = "trstctl/pcas/kem-data-key/v1\x00"

// MaxKEMDataKeyBytes bounds the plaintext a data-key envelope may carry: a
// data key, not data.
const MaxKEMDataKeyBytes = 256

// KEMDataKeyKEK derives the 32-byte AEAD key for one envelope from the KEM
// shared secret and the envelope binding. The caller wipes the result.
func KEMDataKeyKEK(sharedSecret, aad []byte) ([]byte, error) {
	if len(sharedSecret) < 16 {
		return nil, errors.New("crypto: KEM shared secret too short for a data-key envelope")
	}
	h := sha256.New()
	var n [4]byte
	h.Write([]byte(kemDataKeyDomain))
	binary.BigEndian.PutUint32(n[:], lengthPrefix(len(sharedSecret)))
	h.Write(n[:])
	h.Write(sharedSecret)
	binary.BigEndian.PutUint32(n[:], lengthPrefix(len(aad)))
	h.Write(n[:])
	h.Write(aad)
	return h.Sum(nil), nil
}

// KEMDataKeySeal seals dek under the key derived from sharedSecret and aad.
func KEMDataKeySeal(sharedSecret, dek, aad []byte) ([]byte, error) {
	if len(dek) == 0 || len(dek) > MaxKEMDataKeyBytes {
		return nil, errors.New("crypto: KEM data key must be 1 to 256 bytes")
	}
	kek, err := KEMDataKeyKEK(sharedSecret, aad)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(kek)
	return AESGCMSeal(kek, dek, aad)
}

// KEMDataKeyOpen opens an envelope produced by KEMDataKeySeal. The caller
// wipes the returned data key.
func KEMDataKeyOpen(sharedSecret, wrapped, aad []byte) ([]byte, error) {
	kek, err := KEMDataKeyKEK(sharedSecret, aad)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(kek)
	dek, err := AESGCMOpen(kek, wrapped, aad)
	if err != nil {
		return nil, errors.New("crypto: KEM data-key envelope did not open")
	}
	if len(dek) == 0 || len(dek) > MaxKEMDataKeyBytes {
		secret.Wipe(dek)
		return nil, errors.New("crypto: KEM data-key envelope carried an invalid key length")
	}
	return dek, nil
}

// lengthPrefix encodes a field length for the KDF transcript; inputs are
// bounded far below the uint32 range, the clamp only makes the conversion total.
func lengthPrefix(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
