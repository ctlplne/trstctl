// SPDX-License-Identifier: BUSL-1.1

// Package bwsm holds the client-side cryptography a Bitwarden Secrets
// Manager machine account needs to read its organization's secrets (OD-13):
// parsing the access token, deriving the token's key, and opening the
// type-2 encrypted strings (AES-256-CBC with an HMAC-SHA256 tag) the service
// stores names, values and notes as. It follows Bitwarden's open-source SDK
// (bitwarden/sdk-internal: access_token.rs, shareable_key.rs,
// enc_string/symmetric.rs). Keys live in locked secret buffers the caller
// destroys; plaintext is returned as bytes the caller wipes.
package bwsm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// ErrAccessToken is a machine-account access token that does not parse.
var ErrAccessToken = errors.New("bwsm: malformed access token")

// ErrEncString is an encrypted string that does not parse or whose tag does
// not verify under the key.
var ErrEncString = errors.New("bwsm: encrypted string does not open")

// AccessToken is a parsed "0.<access token id>.<client secret>:<key>" token.
// ClientSecret and the key seed are secret; Destroy wipes both.
type AccessToken struct {
	ID           string
	ClientSecret *secret.Buffer
	seed         *secret.Buffer
}

// ParseAccessToken parses a machine-account access token: version "0", a
// UUID access token ID, the client secret, and a base64 16-byte key seed.
func ParseAccessToken(raw []byte) (*AccessToken, error) {
	raw = bytes.TrimSpace(raw)
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return nil, ErrAccessToken
	}
	parts := bytes.SplitN(raw[:colon], []byte("."), 3)
	if len(parts) != 3 || string(parts[0]) != "0" || len(parts[2]) == 0 {
		return nil, ErrAccessToken
	}
	id, err := uuid.ParseBytes(parts[1])
	if err != nil {
		return nil, ErrAccessToken
	}
	encoded := bytes.TrimRight(raw[colon+1:], "=")
	if base64.RawStdEncoding.DecodedLen(len(encoded)) != 16 {
		return nil, ErrAccessToken
	}
	seed := make([]byte, 16)
	defer secret.Wipe(seed)
	if n, err := base64.RawStdEncoding.Decode(seed, encoded); err != nil || n != 16 {
		return nil, ErrAccessToken
	}
	clientSecret, err := secret.NewFrom(parts[2])
	if err != nil {
		return nil, err
	}
	seedBuf, err := secret.NewFrom(seed)
	if err != nil {
		clientSecret.Destroy()
		return nil, err
	}
	return &AccessToken{ID: id.String(), ClientSecret: clientSecret, seed: seedBuf}, nil
}

// Destroy wipes the token's secret parts.
func (t *AccessToken) Destroy() {
	if t == nil {
		return
	}
	t.ClientSecret.Destroy()
	t.seed.Destroy()
}

// Key is a 64-byte symmetric key: the AES-256 key, then the HMAC-SHA256 key.
type Key struct{ buf *secret.Buffer }

// Destroy wipes the key.
func (k *Key) Destroy() {
	if k != nil {
		k.buf.Destroy()
	}
}

// KeyFromBytes holds a 64-byte key (an organization key) in a locked buffer.
func KeyFromBytes(raw []byte) (*Key, error) {
	if len(raw) != 64 {
		return nil, errors.New("bwsm: a key is 64 bytes")
	}
	buf, err := secret.NewFrom(raw)
	if err != nil {
		return nil, err
	}
	return &Key{buf: buf}, nil
}

// TokenKey derives the access token's key: HMAC-SHA256 keyed with
// "bitwarden-accesstoken" over the 16-byte seed is the pseudorandom key that
// HKDF-Expand (SHA-256, info "sm-access-token") stretches to 64 bytes.
func (t *AccessToken) TokenKey() (*Key, error) {
	var out *Key
	err := t.seed.Use(func(seed []byte) error {
		mac := hmac.New(sha256.New, []byte("bitwarden-accesstoken"))
		mac.Write(seed)
		prk := mac.Sum(nil)
		defer secret.Wipe(prk)
		stretched, err := hkdf.Expand(sha256.New, prk, "sm-access-token", 64)
		if err != nil {
			return err
		}
		defer secret.Wipe(stretched)
		out, err = KeyFromBytes(stretched)
		return err
	})
	return out, err
}

// Decrypt opens a type-2 encrypted string ("2.<iv>|<data>|<mac>", standard
// base64): the HMAC-SHA256 tag over iv||data under the key's last 32 bytes
// is checked in constant time before AES-256-CBC with the first 32 bytes
// and PKCS#7 padding is undone. The plaintext is the caller's to wipe.
func (k *Key) Decrypt(encrypted string) ([]byte, error) {
	if k == nil {
		return nil, ErrEncString
	}
	body, ok := strings.CutPrefix(strings.TrimSpace(encrypted), "2.")
	if !ok {
		return nil, ErrEncString
	}
	parts := strings.Split(body, "|")
	if len(parts) != 3 {
		return nil, ErrEncString
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	data, err2 := base64.StdEncoding.DecodeString(parts[1])
	tag, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aes.BlockSize || len(tag) != sha256.Size ||
		len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrEncString
	}
	var plain []byte
	err := k.buf.Use(func(key []byte) error {
		mac := hmac.New(sha256.New, key[32:])
		mac.Write(iv)
		mac.Write(data)
		if !hmac.Equal(mac.Sum(nil), tag) {
			return ErrEncString
		}
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return err
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		pad := int(out[len(out)-1])
		if pad == 0 || pad > aes.BlockSize || pad > len(out) {
			secret.Wipe(out)
			return ErrEncString
		}
		for _, b := range out[len(out)-pad:] {
			if int(b) != pad {
				secret.Wipe(out)
				return ErrEncString
			}
		}
		plain = out[:len(out)-pad]
		return nil
	})
	if err != nil {
		return nil, ErrEncString
	}
	return plain, nil
}

// Encrypt seals plaintext as a type-2 encrypted string under the key with a
// fresh random IV. Discovery only decrypts; this is the inverse, for
// in-repository stand-ins and round-trip tests.
func (k *Key) Encrypt(plaintext []byte) (string, error) {
	if k == nil {
		return "", errors.New("bwsm: no key")
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	defer secret.Wipe(padded)
	var out string
	err := k.buf.Use(func(key []byte) error {
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return err
		}
		data := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, padded)
		mac := hmac.New(sha256.New, key[32:])
		mac.Write(iv)
		mac.Write(data)
		out = "2." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(data) + "|" +
			base64.StdEncoding.EncodeToString(mac.Sum(nil))
		return nil
	})
	return out, err
}
