// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// CR-188: custody-minted CA and agent keys belong to in-signer issuance. A
// socket peer that knows their public handle must not turn either key into a
// generic digest signer, even when it asserts the expected CA purpose.
func TestCR188CustodyMintedKeyRefusesGenericSignAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	store := signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper)
	first, err := signing.NewPersistentServer(store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const handle = "agid-issuing-ca-22222222-2222-4222-8222-222222222222"
	inside, err := first.GenerateSuccessorKey(handle, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("approved in-signer issuance")
	sig, err := inside.Sign(message, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil || crypto.VerifyMessage(inside.Public().DER, message, sig) != nil {
		t.Fatalf("in-signer custody path cannot sign and verify: %v", err)
	}
	request := &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, Digest: crypto.SHA256Sum([]byte("attacker-chosen certificate")),
		Hash: signerpb.Hash_HASH_SHA256, Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
	}
	if _, err := first.Sign(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("generic Sign before restart = %v, want FailedPrecondition", err)
	}
	first.Shutdown()
	second, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()
	if _, err := second.Sign(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("generic Sign after restart = %v, want FailedPrecondition", err)
	}
	restored, err := second.ResolvePredecessor(handle)
	if err != nil {
		t.Fatal(err)
	}
	restoredSignature, err := restored.Sign(message, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil || crypto.VerifyMessage(restored.Public().DER, message, restoredSignature) != nil {
		t.Fatalf("restored in-signer custody path cannot sign and verify: %v", err)
	}
}

// Old sealed files lack the custodyOnly flag. The reserved production handle
// namespaces must still refuse generic Sign after upgrading the signer.
func TestCR188LegacyCustodyHandleNamespacesRefuseGenericSign(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	first, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper))
	if err != nil {
		t.Fatal(err)
	}
	handles := []string{
		"agid-issuing-ca-22222222-2222-4222-8222-222222222222",
		"agid-agent:0123456789abcdef0123456789abcdef",
		"pcas:v2:0123456789abcdef:2",
		"ordinary-app-key",
	}
	for _, handle := range handles {
		if _, err := first.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
			Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: handle,
		}); err != nil {
			t.Fatal(err)
		}
	}
	first.Shutdown()
	second, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()
	for _, handle := range handles {
		_, err := second.Sign(context.Background(), &signerpb.SignRequest{
			Handle: &signerpb.KeyHandle{Id: handle}, Digest: crypto.SHA256Sum([]byte("peer-chosen digest")),
			Hash: signerpb.Hash_HASH_SHA256, Purpose: signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN,
		})
		if handle == "ordinary-app-key" {
			if err != nil {
				t.Fatalf("ordinary key generic Sign = %v, want success", err)
			}
		} else if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("legacy custody handle %q generic Sign = %v, want FailedPrecondition", handle, err)
		}
	}
}
