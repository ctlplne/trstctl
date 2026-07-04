// SPDX-License-Identifier: MPL-2.0

package crypto

import "testing"

// FuzzOpenEnvelope feeds arbitrary bytes into the envelope-decryption path (the
// at-rest form of every stored secret). It must never panic and must never return
// plaintext for a forged envelope — it fails closed on any malformed input.
func FuzzOpenEnvelope(f *testing.F) {
	f.Add([]byte("wrapped"), []byte("dnonce"), []byte("nonce"), []byte("ct"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, wrapped, dnonce, nonce, ct []byte) {
		kek := make([]byte, 32) // valid-length but all-zero KEK
		if _, err := OpenEnvelope(kek, Envelope{WrappedDEK: wrapped, DEKNonce: dnonce, Nonce: nonce, Ciphertext: ct}, []byte("aad")); err == nil {
			t.Fatalf("OpenEnvelope accepted a forged envelope")
		}
	})
}
