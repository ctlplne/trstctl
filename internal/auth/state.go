package auth

import (
	"encoding/base64"

	"certctl.io/certctl/internal/crypto"
)

// RandomState returns a cryptographically-random, URL-safe value suitable for an
// OIDC state or nonce. Randomness comes through the crypto boundary (AN-3).
func RandomState() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
