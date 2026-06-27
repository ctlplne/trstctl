package auth

import (
	"encoding/base64"

	"trstctl.com/trstctl/internal/crypto"
)

const PKCEChallengeMethodS256 = "S256"

// RandomState returns a cryptographically-random, URL-safe value suitable for an
// OIDC state or nonce. Randomness comes through the crypto boundary (AN-3).
func RandomState() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GeneratePKCEVerifier returns a high-entropy PKCE verifier. It uses 32 random
// bytes, which encode to 43 base64url characters: the RFC 7636 lower bound.
func GeneratePKCEVerifier() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PKCEChallengeS256 derives the RFC 7636 S256 code_challenge from verifier.
func PKCEChallengeS256(verifier string) string {
	return crypto.SHA256Base64URL([]byte(verifier))
}
