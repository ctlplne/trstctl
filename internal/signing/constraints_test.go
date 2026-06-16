package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestSignRefusesDisallowedPurpose is the SIGNER-002/003 / RED-003 acceptance
// test: a key created with a constrained allowed-purpose set refuses to sign for
// any other purpose (FAILED_PRECONDITION), and refuses a Sign that asserts no
// purpose at all — so a caller with socket access and the handle cannot coerce
// the key into minting trust outside its mandate. It exercises the real server
// handler (the path the served binary uses).
//
// Pre-fix this test cannot even be written (no purpose field) and the underlying
// behavior is the bug: the signer signs ANY digest for ANY purpose given only
// the handle.
func TestSignRefusesDisallowedPurpose(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()

	// A CA-class key: may only be used for CA signing.
	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "issuing-ca",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := make([]byte, 32)

	// Allowed purpose → signs.
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle:  gen.GetHandle(),
		Digest:  digest,
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}); err != nil {
		t.Fatalf("Sign with allowed purpose CA_SIGN failed: %v", err)
	}

	// Disallowed purposes → refused with FAILED_PRECONDITION. This is the
	// fleet-forge oracle being closed: the CA key cannot be turned into an SSH /
	// code-signing / arbitrary-leaf signer.
	for _, p := range []signerpb.KeyPurpose{
		signerpb.KeyPurpose_KEY_PURPOSE_SSH_CERT,
		signerpb.KeyPurpose_KEY_PURPOSE_CODE_SIGN,
		signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS,
		signerpb.KeyPurpose_KEY_PURPOSE_GENERIC,
	} {
		_, err := s.Sign(ctx, &signerpb.SignRequest{
			Handle:  gen.GetHandle(),
			Digest:  digest,
			Hash:    signerpb.Hash_HASH_SHA256,
			Purpose: p,
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("Sign with disallowed purpose %v: got %v, want FailedPrecondition", p, status.Code(err))
		}
	}

	// No asserted purpose against a constrained key → refused. A caller that
	// just sends a digest (the pre-fix attack) is rejected.
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle: gen.GetHandle(),
		Digest: digest,
		Hash:   signerpb.Hash_HASH_SHA256,
		// Purpose left UNSPECIFIED
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("Sign with no asserted purpose on a constrained key: got %v, want FailedPrecondition", status.Code(err))
	}
}

// TestSignRefusesDisallowedHash proves the optional allowed-hash constraint: a
// key bound to SHA-256 refuses a SHA-384/512 digest.
func TestSignRefusesDisallowedHash(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()

	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS},
		AllowedHashes:   []signerpb.Hash{signerpb.Hash_HASH_SHA256},
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// SHA-256 (allowed) signs.
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle:  gen.GetHandle(),
		Digest:  make([]byte, 32),
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS,
	}); err != nil {
		t.Fatalf("Sign with allowed hash SHA-256 failed: %v", err)
	}

	// SHA-384 (not allowed) refused.
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle:  gen.GetHandle(),
		Digest:  make([]byte, 48),
		Hash:    signerpb.Hash_HASH_SHA384,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_LEAF_TLS,
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("Sign with disallowed hash SHA-384: got %v, want FailedPrecondition", status.Code(err))
	}
}

// TestUnconstrainedKeyAcceptsAnyPurpose proves back-compat: a key created with
// NO allowed-purpose set (the default / pre-constraint behavior) still signs for
// any purpose, so existing callers and ephemeral keys keep working.
func TestUnconstrainedKeyAcceptsAnyPurpose(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()
	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	for _, p := range []signerpb.KeyPurpose{
		signerpb.KeyPurpose_KEY_PURPOSE_UNSPECIFIED,
		signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
		signerpb.KeyPurpose_KEY_PURPOSE_SSH_CERT,
	} {
		if _, err := s.Sign(ctx, &signerpb.SignRequest{
			Handle:  gen.GetHandle(),
			Digest:  make([]byte, 32),
			Hash:    signerpb.Hash_HASH_SHA256,
			Purpose: p,
		}); err != nil {
			t.Errorf("unconstrained key should accept purpose %v, got %v", p, err)
		}
	}
}

// TestGenerateRejectsUnspecifiedInAllowSet guards the constraint-construction
// rule: allowing UNSPECIFIED would create a key that the (also-UNSPECIFIED)
// default Sign could always use, defeating the constraint.
func TestGenerateRejectsUnspecifiedInAllowSet(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()
	if _, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_UNSPECIFIED},
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("GenerateKey allowing UNSPECIFIED purpose: got %v, want InvalidArgument", status.Code(err))
	}
}

// TestConstraintsSurviveRestart proves the per-key constraint is persisted in the
// sealed keystore and re-enforced after a signer restart (SIGNER-003 acceptance:
// "constraint survives a restart"). Boot 1 creates a CA-purpose key; boot 2 (a
// fresh server over the same sealed store) still refuses a non-CA purpose.
func TestConstraintsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	ctx := context.Background()

	s1, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 1: %v", err)
	}
	if _, err := s1.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "issuing-ca",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	s2, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 2: %v", err)
	}
	handle := &signerpb.KeyHandle{Id: "issuing-ca"}
	digest := make([]byte, 32)

	// CA purpose still allowed after restart.
	if _, err := s2.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}); err != nil {
		t.Fatalf("CA-purpose sign after restart failed: %v", err)
	}
	// Disallowed purpose still refused after restart — the constraint was sealed
	// and restored, not lost.
	if _, err := s2.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_SSH_CERT,
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("disallowed purpose after restart: got %v, want FailedPrecondition", status.Code(err))
	}
}

// TestServedCAKeyRefusesForgeryOverUDS is the end-to-end served-path proof: the
// signer runs as its own process (the AN-4 boundary), a CA-purpose key is
// created over the real UDS, and a Sign asserting a different purpose is refused
// by the running signer — exactly the forge-the-fleet surface (RED-003) being
// constrained at the served boundary, not just in a unit test.
func TestServedCAKeyRefusesForgeryOverUDS(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- signing.Serve(ctx, socket) }()

	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	// Create a CA-purpose key over the wire and sign legitimately through it.
	caSigner, err := client.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, "issuing-ca",
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("GenerateConstrainedKeyHandle: %v", err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("legit CA TBS"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caSigner.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("legitimate CA-purpose sign over UDS failed: %v", err)
	}

	// Now act as the attacker: bind the SAME well-known handle but assert a
	// forging purpose (SSH cert). The running signer must refuse.
	forger, err := client.SignerForHandleWithPurpose(ctx, "issuing-ca", signing.PurposeSSHCert)
	if err != nil {
		t.Fatalf("SignerForHandleWithPurpose: %v", err)
	}
	_, err = forger.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("forging Sign over UDS: got %v, want FailedPrecondition (the CA key must not sign an SSH cert)", status.Code(err))
	}

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
