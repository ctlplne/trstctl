// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSealAnonymousCurve25519MatchesLibsodiumWireContract(t *testing.T) {
	pub, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("github-actions-secret-value")
	sealed, err := SealAnonymousCurve25519(base64.StdEncoding.EncodeToString(pub[:]), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, sealed, pub, private)
	if !ok {
		t.Fatal("sealed box did not open with the repository key")
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("opened = %q, want original plaintext", opened)
	}
}

func TestSealAnonymousCurve25519RejectsMalformedKey(t *testing.T) {
	if _, err := SealAnonymousCurve25519(base64.StdEncoding.EncodeToString([]byte("short")), []byte("secret")); err == nil {
		t.Fatal("short public key was accepted")
	}
}
