// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestFederationTrustRootMustBeAUsableKey is the regression guard for the
// unvalidated trust anchor.
//
// RequestFederationImport persisted ForeignTrustRootDER — a TRUST ANCHOR, the
// value a foreign deployment's succession chain is later verified against —
// straight into the bridge table with no check that the bytes were a key at all.
// The handler required the field to be non-empty and nothing more. The old test
// fixture for this path was literally []byte("foreign-root-der-bytes") and round
// tripped happily, which is the defect restating itself.
//
// Rejecting at the request means an unusable anchor fails where the caller can
// see it, rather than much later inside a worker, against a stored row that
// already looks authoritative.
func TestFederationTrustRootMustBeAUsableKey(t *testing.T) {
	t.Run("rejects bytes that are not a key", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			der  []byte
		}{
			{"empty", nil},
			{"placeholder text", []byte("foreign-root-der-bytes")},
			{"truncated DER", []byte{0x30, 0x59, 0x30, 0x13}},
			{"random bytes", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := validateForeignTrustRoot(tc.der)
				if err == nil {
					t.Fatal("accepted as a federation trust anchor; a foreign chain would later be " +
						"verified against bytes that are not a key")
				}
				if !strings.Contains(err.Error(), "trust root") {
					t.Errorf("error should name the field an operator has to fix, got: %v", err)
				}
			})
		}
	})

	t.Run("accepts real public keys", func(t *testing.T) {
		// Despite the "DER" in the field name this is a PKIX SubjectPublicKeyInfo,
		// not a certificate: VerifyGenesis hands it to crypto.VerifyMessage.
		for _, alg := range []crypto.Algorithm{crypto.ECDSAP256, crypto.RSA2048} {
			key, err := crypto.GenerateLockedKey(alg)
			if err != nil {
				t.Fatalf("generate %v: %v", alg, err)
			}
			t.Cleanup(key.Destroy)
			if err := validateForeignTrustRoot(key.Public().DER); err != nil {
				t.Errorf("a real %v public key was rejected: %v", alg, err)
			}
		}
	})

	t.Run("rejects a certificate where a bare key belongs", func(t *testing.T) {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		certDER, err := crypto.SelfSignedCACert(key, "Foreign Root", 0)
		if err != nil {
			t.Skipf("could not build a certificate fixture: %v", err)
		}
		if err := validateForeignTrustRoot(certDER); err == nil {
			t.Error("a certificate was accepted where a SubjectPublicKeyInfo is expected; " +
				"VerifyMessage would fail against it later")
		}
	})
}
