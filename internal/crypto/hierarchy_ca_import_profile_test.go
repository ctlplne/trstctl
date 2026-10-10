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
}
