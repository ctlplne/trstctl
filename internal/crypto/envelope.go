package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Envelope is an envelope-encrypted secret: the plaintext is encrypted under a
// per-secret data key (DEK) with AES-256-GCM, and the DEK is itself wrapped under
// the key-encryption key (KEK) with AES-256-GCM. This is the at-rest storage form
// for the secret store (S16.3); the KEK lives in software or an HSM (S9.x). All
// material is []byte and DEKs are zeroized after use (AN-8).
type Envelope struct {
	WrappedDEK []byte `json:"wrapped_dek"`
	DEKNonce   []byte `json:"dek_nonce"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// NewKEK generates a 32-byte (AES-256) key-encryption key.
func NewKEK() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("crypto: generate KEK: %w", err)
	}
	return k, nil
}

// SealEnvelope envelope-encrypts plaintext under kek (32 bytes). aad is additional
// authenticated data (e.g. tenant+path) bound to the ciphertext so a sealed value
// cannot be moved to another location.
func SealEnvelope(kek, plaintext, aad []byte) (Envelope, error) {
	if len(kek) != 32 {
		return Envelope{}, fmt.Errorf("crypto: KEK must be 32 bytes (AES-256)")
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, err
	}
	defer zero(dek)
	ct, nonce, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	wrapped, dnonce, err := gcmSeal(kek, dek, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{WrappedDEK: wrapped, DEKNonce: dnonce, Nonce: nonce, Ciphertext: ct}, nil
}

// OpenEnvelope decrypts an Envelope under kek with the same aad. A wrong KEK,
// tampered ciphertext, or mismatched aad fails authentication.
func OpenEnvelope(kek []byte, env Envelope, aad []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("crypto: KEK must be 32 bytes (AES-256)")
	}
	dek, err := gcmOpen(kek, env.WrappedDEK, env.DEKNonce, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	defer zero(dek)
	pt, err := gcmOpen(dek, env.Ciphertext, env.Nonce, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt secret: %w", err)
	}
	return pt, nil
}

func gcmSeal(key, plaintext, aad []byte) (ct, nonce []byte, err error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return g.Seal(nil, nonce, plaintext, aad), nonce, nil
}

func gcmOpen(key, ct, nonce, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
