// SPDX-License-Identifier: BUSL-1.1

package bwsm

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// FuzzParseAccessToken exercises the machine-account token boundary, including
// its UUID, separators, and base64 seed. Successful parses must stay usable.
func FuzzParseAccessToken(f *testing.F) {
	f.Add([]byte(vectorToken))
	f.Add([]byte("0.bad-id.secret:not-base64"))
	f.Add([]byte{0, ':', '.', 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		token, err := ParseAccessToken(raw)
		if err != nil {
			if token != nil {
				t.Fatal("failed parse returned secret material")
			}
			return
		}
		if token == nil {
			t.Fatal("successful parse returned no token")
		}
		defer token.Destroy()
		key, err := token.TokenKey()
		if err != nil {
			t.Fatalf("parsed token cannot derive its key: %v", err)
		}
		key.Destroy()
	})
}

// FuzzDecrypt exercises the encrypted-string framing, tag check, and padding
// decoder under one fixed non-secret key. Valid ciphertext is part of the seed.
func FuzzDecrypt(f *testing.F) {
	key, err := KeyFromBytes(bytes.Repeat([]byte{7}, 64))
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Cleanup(key.Destroy)
	valid, err := key.Encrypt([]byte("seed"))
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add(valid)
	f.Add("2.!!!|!!!|!!!")
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 4096 {
			return
		}
		plain, err := key.Decrypt(encoded)
		if err == nil && plain == nil {
			t.Fatal("successful decryption returned no plaintext")
		}
		secret.Wipe(plain)
	})
}
