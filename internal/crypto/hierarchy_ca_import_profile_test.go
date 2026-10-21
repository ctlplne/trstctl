// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestImportedOfflineRootCannotOutrunReviewedKeyAndValidity(t *testing.T) {
	profile := crypto.HierarchyCAProfile{
		CommonName: "Offline root profile binding", MaxPathLen: 1,
		TTL: 365 * 24 * time.Hour, SignatureAlgorithm: "ECDSA-P256",
	}
	p256, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p256.Destroy)
	root, err := crypto.SelfSignedHierarchyCA(p256, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyImportedOfflineRoot(root.CertificateDER, profile); err != nil {
		t.Fatalf("matching reviewed offline root: %v", err)
	}
	short := profile
	short.TTL = 30 * 24 * time.Hour
	if _, err := crypto.VerifyImportedOfflineRoot(root.CertificateDER, short); err == nil || !strings.Contains(err.Error(), "ttl_seconds") {
		t.Fatalf("root outliving reviewed horizon = %v; want refusal", err)
	}

	rsa, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rsa.Destroy)
	rsaRoot, err := crypto.SelfSignedHierarchyCA(rsa, profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyImportedOfflineRoot(rsaRoot.CertificateDER, profile); err == nil || !strings.Contains(err.Error(), "ECDSA-P256") {
		t.Fatalf("RSA root reviewed as P-256 = %v; want refusal", err)
	}

	// A25: every verifiable key algorithm imports under its own reviewed label,
	// and only under its own label.
	for _, tc := range []struct {
		algorithm crypto.Algorithm
		label     string
	}{
		{crypto.ECDSAP384, "ecdsa-p384"}, {crypto.ECDSAP521, "ECDSA-P521"},
		{crypto.RSA2048, "rsa-2048"}, {crypto.RSA3072, "RSA-3072"},
	} {
		key, err := crypto.GenerateLockedKey(tc.algorithm)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		reviewed := profile
		reviewed.SignatureAlgorithm = tc.label
		root, err := crypto.SelfSignedHierarchyCA(key, reviewed)
		if err != nil {
			t.Fatalf("%s root: %v", tc.label, err)
		}
		if _, err := crypto.VerifyImportedOfflineRoot(root.CertificateDER, reviewed); err != nil {
			t.Fatalf("%s root reviewed as %s refused: %v", tc.algorithm, tc.label, err)
		}
		if _, err := crypto.VerifyImportedOfflineRoot(root.CertificateDER, profile); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("%s root reviewed as P-256 = %v; want a mismatch refusal", tc.algorithm, err)
		}
	}
	// Ed25519 roots are minted outside trstctl (the served signer does not
	// hold Ed25519 CA keys), so the fixture is built with the standard library
	// the way an air-gapped tool would build it.
	edRoot := crypto.Ed25519SelfSignedRootDERForTest(t, profile)
	edReviewed := profile
	edReviewed.SignatureAlgorithm = "Ed25519"
	if _, err := crypto.VerifyImportedOfflineRoot(edRoot, edReviewed); err != nil {
		t.Fatalf("Ed25519 root reviewed as ed25519 refused: %v", err)
	}
	if _, err := crypto.VerifyImportedOfflineRoot(edRoot, profile); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Ed25519 root reviewed as P-256 = %v; want a mismatch refusal", err)
	}
	unsupported := profile
	unsupported.SignatureAlgorithm = "rsa-1024"
	if _, err := crypto.VerifyImportedOfflineRoot(root.CertificateDER, unsupported); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported reviewed label = %v; want refusal", err)
	}
}

func TestExistingCAIssuerPreparationRequiresUsableSigningChain(t *testing.T) {
	issuerKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerKey.Destroy)
	issuer, err := crypto.SelfSignedHierarchyCA(issuerKey, crypto.HierarchyCAProfile{
		CommonName: "prepared issuer", MaxPathLen: 1, TTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyExistingCAIssuerChain([][]byte{issuer.CertificateDER}); err != nil {
		t.Fatalf("usable issuer refused: %v", err)
	}
	exhaustedKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exhaustedKey.Destroy)
	exhausted, err := crypto.SelfSignedHierarchyCA(exhaustedKey, crypto.HierarchyCAProfile{
		CommonName: "exhausted issuer", MaxPathLen: 0, TTL: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyExistingCAIssuerChain([][]byte{exhausted.CertificateDER}); err == nil || !strings.Contains(err.Error(), "cannot sign another intermediate") {
		t.Fatalf("exhausted issuer accepted: %v", err)
	}
	if _, err := crypto.VerifyExistingCAIssuerChain([][]byte{issuer.CertificateDER, exhausted.CertificateDER}); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unrelated issuer chain accepted: %v", err)
	}
}
