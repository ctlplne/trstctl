package awskms_test

import (
	"context"
	"testing"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/kms/awskms"
)

// TestAWSKMSRemoteKeyLifecycle drives a KMS-resident BYOK/HSM key through the full
// remote lifecycle (EXC-CRYPTO-01): generate → sign → rotate (successor signs;
// old key still usable until retired) → revoke (KMS refuses to sign) → zeroize
// (KMS refuses to sign). The private key never leaves KMS, so "zeroize" is a remote
// ScheduleKeyDeletion, not a local buffer wipe. It runs against the in-process KMS
// double, which faithfully refuses Sign for a disabled / pending-deletion key.
//
// This exercises crypto.RemoteKeyLifecycle, the interface that lets an HSM/KMS key
// participate in the same generate→rotate→revoke→zeroize lifecycle as the
// in-process secret.Buffer-backed key.
func TestAWSKMSRemoteKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS(t)
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: testSK},
		awskms.WithEndpoint(f.srv.URL), awskms.WithHTTPClient(f.srv.Client()))

	// The backend must satisfy the remote-lifecycle contract.
	var lc crypto.RemoteKeyLifecycle = b

	opts := crypto.SignOptions{Hash: crypto.SHA256}
	msg := []byte("kms lifecycle probe")

	// Generate a managed key and sign with it.
	signer, ref, err := lc.GenerateManagedKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateManagedKey: %v", err)
	}
	if ref.ID == "" || ref.Algorithm != crypto.ECDSAP256 {
		t.Fatalf("unexpected key ref: %+v", ref)
	}
	sig, err := signer.Sign(msg, opts)
	if err != nil {
		t.Fatalf("sign with managed key: %v", err)
	}
	if err := crypto.Verify(signer.Public(), msg, sig, opts); err != nil {
		t.Fatalf("managed-key signature did not verify: %v", err)
	}

	// Rotate: a successor key signs and verifies under its own public key.
	succSigner, succRef, err := lc.RotateKey(ctx, ref)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if succRef.ID == ref.ID {
		t.Fatalf("rotation returned the same key id %q — not a successor", succRef.ID)
	}
	sSig, err := succSigner.Sign(msg, opts)
	if err != nil {
		t.Fatalf("sign with successor key: %v", err)
	}
	if err := crypto.Verify(succSigner.Public(), msg, sSig, opts); err != nil {
		t.Fatalf("successor-key signature did not verify: %v", err)
	}

	// Revoke the original key: KMS must now refuse to sign with it (fail-closed).
	if err := lc.RevokeKey(ctx, ref); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := signer.Sign(msg, opts); err == nil {
		t.Fatalf("a revoked (disabled) KMS key still signed — not fail-closed")
	}

	// Zeroize the original key: still refused (pending deletion at the provider).
	if err := lc.ZeroizeKey(ctx, ref); err != nil {
		t.Fatalf("ZeroizeKey: %v", err)
	}
	if _, err := signer.Sign(msg, opts); err == nil {
		t.Fatalf("a zeroized (pending-deletion) KMS key still signed — not fail-closed")
	}

	// The successor remains usable — revoking/zeroizing the predecessor did not
	// affect the rotated-to key.
	if _, err := succSigner.Sign(msg, opts); err != nil {
		t.Fatalf("successor key broke after retiring the predecessor: %v", err)
	}
}
