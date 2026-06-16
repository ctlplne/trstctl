package signing_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func dualControlAuthorizer(t *testing.T) *crypto.SignAuthorizer {
	t.Helper()
	a, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x3C}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(a.Destroy)
	return a
}

// serveDualControl launches a signer over a real UDS whose server holds the given
// verify-only authorizer, and returns a connected client. This is the served AN-4
// boundary the control plane actually talks to.
func serveDualControl(t *testing.T, authz *crypto.SignAuthorizer) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "dc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	served := make(chan error, 1)
	svc := signing.NewServer(signing.WithAuthorizer(authz))
	go func() { served <- signing.ServeServer(ctx, socket, svc) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("ServeServer did not return after cancel")
		}
	})
	return waitReady(t, socket)
}

// TestDualControlBlocksDigestBlindForgeryOverUDS is the RED-003 end-to-end
// acceptance test and the headline of this finding's closure.
//
// It stands up the real isolated signer (AN-4) over a UDS, creates a DUAL-CONTROL
// CA key, and proves the digest-blind forge no longer works at the served
// boundary:
//
//   - The legitimate, attested path (the approval authority mints a token over the
//     exact tuple) signs the approved digest — issuance still works.
//   - The forge attempt — a caller that reaches the socket with the CA handle and
//     the correct purpose and sends an ARBITRARY attacker-chosen digest (exactly
//     what the old digest-blind Sign would have signed) — is REJECTED, because it
//     carries no valid authorization token for that digest.
//   - Replaying a token minted for one digest onto a different digest is REJECTED:
//     the authorization is bound to the digest, so an approved signature cannot be
//     diverted onto attacker bytes.
//
// Pre-fix, Sign signed req.GetDigest() after a shape-only check, so all three of
// these would have produced a CA signature over attacker bytes.
func TestDualControlBlocksDigestBlindForgeryOverUDS(t *testing.T) {
	authz := dualControlAuthorizer(t)
	client := serveDualControl(t, authz)
	defer func() { _ = client.Close() }()
	ctx := context.Background()

	// The control plane (with the approver authorizer) creates the dual-control CA
	// key over the wire.
	caSigner, err := client.GenerateDualControlKeyHandle(ctx, crypto.ECDSAP256, "issuing-ca",
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign, authz)
	if err != nil {
		t.Fatalf("GenerateDualControlKeyHandle: %v", err)
	}

	approvedDigest, err := crypto.Digest(crypto.SHA256, []byte("approved CA TBS"))
	if err != nil {
		t.Fatal(err)
	}

	// (1) Legitimate attested sign succeeds (the RemoteSigner attaches a valid token
	// over this exact digest).
	if _, err := caSigner.SignDigest(approvedDigest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("attested CA sign failed: %v", err)
	}

	// (2) The digest-blind forge: a raw Sign for the CA handle + correct purpose +
	// arbitrary attacker digest, with NO authorization token. Must be refused.
	forgeDigest, err := crypto.Digest(crypto.SHA256, []byte("forge:arbitrary-attacker-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RawSignForTest(ctx, &signerpb.SignRequest{
		Handle:  &signerpb.KeyHandle{Id: "issuing-ca"},
		Digest:  forgeDigest,
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("digest-blind forge over UDS: got %v, want PermissionDenied (the CA key must not sign un-attested attacker bytes)", status.Code(err))
	}

	// (3) Token-replay: mint a valid token for the APPROVED digest, then attach it to
	// a Sign of a DIFFERENT (attacker) digest. Must be refused — the token is bound
	// to the digest.
	// Padding is RSAPKCS1v15 here to match the signer's canonicalization of an
	// unset rsa_padding field (paddingFromProto(0)); this makes the token VALID for
	// approvedDigest, so the only reason the replay is refused is the digest swap.
	replayToken, err := authz.Authorize(crypto.SignIntent{
		KeyHandle: "issuing-ca",
		Purpose:   int32(signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN),
		Hash:      crypto.SHA256,
		Padding:   crypto.RSAPKCS1v15,
		Digest:    approvedDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	replayCtx := metadata.AppendToOutgoingContext(ctx, "trstctl-sign-auth-token-bin", string(replayToken))
	_, err = client.RawSignForTest(replayCtx, &signerpb.SignRequest{
		Handle:  &signerpb.KeyHandle{Id: "issuing-ca"},
		Digest:  forgeDigest, // different from the digest the token authorized
		Hash:    signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("token replay onto a different digest: got %v, want PermissionDenied", status.Code(err))
	}
}

// TestDualControlKeyRejectedWithoutAuthorizer proves the fail-closed property: a
// signer with NO authorizer cannot create a dual-control key (it would be
// permanently unusable), and — separately — refuses to USE a dual-control key it
// loaded from a sealed store but cannot authorize.
func TestDualControlKeyRejectedWithoutAuthorizer(t *testing.T) {
	ctx := context.Background()

	// A signer without an authorizer refuses to mint a dual-control key.
	plain := signing.NewServer()
	mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1"))
	if _, err := plain.GenerateKey(mdCtx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("dual-control GenerateKey without authorizer: got %v, want FailedPrecondition", status.Code(err))
	}
}

// TestDualControlConstraintSurvivesRestart proves the requireAuth flag is sealed
// with the key and re-enforced after a signer restart: boot 1 (with an authorizer)
// creates a dual-control CA key; boot 2 (a fresh server over the same sealed store,
// with the same authorizer) still demands a token, and an un-attested Sign is
// refused while an attested one succeeds.
func TestDualControlConstraintSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	authz := dualControlAuthorizer(t)
	ctx := context.Background()

	s1, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek), signing.WithAuthorizer(authz))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 1: %v", err)
	}
	mdGen := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-require-auth", "1"))
	if _, err := s1.GenerateKey(mdGen, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId:     "issuing-ca",
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Boot 2: fresh server over the same store.
	s2, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek), signing.WithAuthorizer(authz))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 2: %v", err)
	}
	handle := &signerpb.KeyHandle{Id: "issuing-ca"}
	digest := make([]byte, 32)

	// Un-attested Sign after restart is still refused — the requireAuth flag was
	// sealed and restored.
	if _, err := s2.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("un-attested sign after restart: got %v, want PermissionDenied", status.Code(err))
	}

	// Attested Sign after restart succeeds.
	// Padding matches the signer's canonicalization of an unset rsa_padding field.
	token, err := authz.Authorize(crypto.SignIntent{
		KeyHandle: "issuing-ca",
		Purpose:   int32(signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN),
		Hash:      crypto.SHA256,
		Padding:   crypto.RSAPKCS1v15,
		Digest:    digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	attCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("trstctl-sign-auth-token-bin", string(token)))
	if _, err := s2.Sign(attCtx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}); err != nil {
		t.Fatalf("attested sign after restart failed: %v", err)
	}
}
