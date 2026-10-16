// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
)

func TestVerifyAlgorithmMessagePostQuantumSignerDigest(t *testing.T) {
	for _, algorithm := range []crypto.Algorithm{pqc.MLDSA65, pqc.SLHDSA128s} {
		t.Run(string(algorithm), func(t *testing.T) {
			var key crypto.DigestSigner
			var destroy func()
			if algorithm == pqc.MLDSA65 {
				generated, err := pqc.GenerateKey(algorithm)
				if err != nil {
					t.Fatal(err)
				}
				key, destroy = generated, generated.Destroy
			} else {
				generated, err := pqc.GenerateSLHDSAKey(algorithm)
				if err != nil {
					t.Fatal(err)
				}
				key, destroy = generated, generated.Destroy
			}
			defer destroy()
			message := []byte("trstctl/pcas/pqc-verification/test")
			sig, err := crypto.SignerFromDigestSigner(key).Sign(message, crypto.SignOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatal(err)
			}
			if err := crypto.VerifyAlgorithmMessage(key.Public(), message, sig); err != nil {
				t.Fatalf("valid signature: %v", err)
			}
			message[0] ^= 1
			if err := crypto.VerifyAlgorithmMessage(key.Public(), message, sig); err == nil {
				t.Fatal("changed commitment verified")
			}
			wrong := key.Public()
			wrong.Algorithm = pqc.MLDSA44
			if err := crypto.VerifyAlgorithmMessage(wrong, []byte("trstctl/pcas/pqc-verification/test"), sig); err == nil {
				t.Fatal("wrong algorithm label verified")
			}
		})
	}
}
