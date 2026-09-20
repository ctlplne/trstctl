// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// SealAnonymousCurve25519 produces the libsodium crypto_box_seal wire format
// used by GitHub Actions encrypted secrets. The recipient key is the base64
// Curve25519 public key returned by GitHub's public-key endpoint. Cryptographic
// implementation stays behind internal/crypto (AN-3); callers only move bytes.
func SealAnonymousCurve25519(recipientPublicKeyBase64 string, plaintext []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(recipientPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode Curve25519 public key: %w", err)
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) != 32 {
		return nil, errors.New("crypto: Curve25519 public key must be exactly 32 bytes")
	}
	var recipient [32]byte
	copy(recipient[:], raw)
	sealed, err := box.SealAnonymous(nil, plaintext, &recipient, rand.Reader)
	for i := range recipient {
		recipient[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("crypto: anonymous seal: %w", err)
	}
	return sealed, nil
}
