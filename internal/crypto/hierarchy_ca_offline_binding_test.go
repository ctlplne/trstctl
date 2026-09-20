// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// TestVerifyOfflineSignedIntermediateRequiresSignerHeldKey guards the air-gapped
// CA ceremony's key binding.
//
// The ceremony is: the served signer generates a key and emits a CSR, the CSR is
// carried to the offline root, the offline root signs an intermediate, and the
// certificate is carried back and imported. The binding check in
// VerifyOfflineSignedIntermediate is what proves the returned certificate was
// minted over the key the signer actually holds, and not over some other key
// pair. Without it the platform registers an intermediate whose private key it
// does not possess and cannot use — or, worse, one whose private key is held by
// whoever ran the offline step.
//
// Its sibling VerifyImportedCAChain has the identical check covered by an
// internal/server integration test; this path did not, so the binding could be
// deleted with the whole suite still green. The mismatch case below is the one
// that dies when it is removed.
func TestVerifyOfflineSignedIntermediateRequiresSignerHeldKey(t *testing.T) {
	profile := crypto.HierarchyCAProfile{
		CommonName: "trstctl offline intermediate",
		MaxPathLen: 0,
		TTL:        24 * time.Hour,
	}
	rootProfile := crypto.HierarchyCAProfile{
		CommonName: "trstctl offline root",
		MaxPathLen: 1,
		TTL:        72 * time.Hour,
	}

	offlineRoot, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(offlineRoot.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(offlineRoot, rootProfile)
	if err != nil {
		t.Fatal(err)
	}

	// The key the served signer actually holds for this ceremony.
	signerHeld, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signerHeld.Destroy)

	// A different key pair — the ceremony went wrong, or someone substituted one.
	otherKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherKey.Destroy)

	// The offline root correctly signs an intermediate, but over the WRONG key.
	// Everything else about this certificate is valid: real signature from the
	// real root, inside the path-length budget, inside the root's validity.
	wrongKeyCert, err := crypto.SignIntermediateHierarchyCA(root.CertificateDER, offlineRoot, otherKey.Public(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyOfflineSignedIntermediate(
		root.CertificateDER, wrongKeyCert.CertificateDER, signerHeld.Public(), profile,
	); err == nil {
		t.Fatal("an offline-signed intermediate minted over a key the signer does not hold was accepted; the ceremony's signer-key binding is not enforced")
	}

	// Control: the same ceremony done correctly must still import, so the guard
	// above cannot be satisfied by rejecting everything.
	rightKeyCert, err := crypto.SignIntermediateHierarchyCA(root.CertificateDER, offlineRoot, signerHeld.Public(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyOfflineSignedIntermediate(
		root.CertificateDER, rightKeyCert.CertificateDER, signerHeld.Public(), profile,
	); err != nil {
		t.Fatalf("a correctly-performed offline ceremony must import: %v", err)
	}
}
