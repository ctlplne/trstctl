// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func signDigest(s *signing.Server, handle string) error {
	_, err := s.Sign(context.Background(), &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
	})
	return err
}

func revokeKey(s *signing.Server, handle, operationID, reason string) (*signerpb.RevokeKeyResponse, error) {
	return s.RevokeKey(context.Background(), &signerpb.RevokeKeyRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, OperationId: operationID, Reason: reason,
	})
}

// A128: an administratively revoked key keeps its public half readable and can
// still be destroyed, but signs nothing from the revocation on, including as a
// succession predecessor. The first revocation holds: a repeat with another
// operation reads back the original operation, reason and time.
func TestRevokedKeyRefusesSignaturesKeepsItsPublicKeyAndHoldsTheFirstRevocation(t *testing.T) {
	ctx := context.Background()
	s := signing.NewServer()
	pub := genCA(t, s)
	if err := signDigest(s, "issuing-ca"); err != nil {
		t.Fatalf("sign before revocation: %v", err)
	}

	for name, req := range map[string]*signerpb.RevokeKeyRequest{
		"no operation":     {Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, Reason: "key_compromise"},
		"free-text reason": {Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, OperationId: "op-1", Reason: "Key Compromise"},
		"no handle":        {OperationId: "op-1", Reason: "key_compromise"},
	} {
		if _, err := s.RevokeKey(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: RevokeKey = %v, want InvalidArgument", name, err)
		}
	}
	if _, err := revokeKey(s, "no-such-key", "op-1", "key_compromise"); status.Code(err) != codes.NotFound {
		t.Fatalf("revoking an unknown handle = %v, want NotFound", err)
	}

	first, err := revokeKey(s, "issuing-ca", "ceremony-1", "key_compromise")
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if !bytes.Equal(first.GetPublicKey(), pub) || first.GetOperationId() != "ceremony-1" ||
		first.GetReason() != "key_compromise" || first.GetRevokedAtUnix() <= 0 {
		t.Fatalf("revocation readback = %+v", first)
	}
	if err := signDigest(s, "issuing-ca"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("sign after revocation = %v, want FailedPrecondition naming the revocation", err)
	}
	if _, err := s.ResolvePredecessor("issuing-ca"); err == nil {
		t.Fatal("a revoked key resolved as a succession predecessor")
	}
	got, err := s.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
	if err != nil || !bytes.Equal(got.GetPublicKey(), pub) || !got.GetRevoked() {
		t.Fatalf("public key after revocation = %+v, %v; want the same key reported revoked", got, err)
	}

	again, err := revokeKey(s, "issuing-ca", "ceremony-2", "superseded")
	if err != nil {
		t.Fatalf("repeat RevokeKey: %v", err)
	}
	if again.GetOperationId() != "ceremony-1" || again.GetReason() != "key_compromise" || again.GetRevokedAtUnix() != first.GetRevokedAtUnix() {
		t.Fatalf("repeat revocation = %+v, want the first revocation %+v", again, first)
	}

	if _, err := s.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); err != nil {
		t.Fatalf("destroying a revoked key: %v", err)
	}
	if _, err := s.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}}); status.Code(err) != codes.NotFound {
		t.Fatalf("public key after destruction = %v, want NotFound", err)
	}
}

// A revocation is durable shared keystore state: a signer process that already
// holds the key refuses it on its next signature, and so does a signer started
// after the revocation, which also reads back the original record.
func TestRevokedKeyIsRefusedByEverySignerSharingTheKeystore(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	ctx := context.Background()
	a, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	b, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	pub := genCA(t, a)
	if err := signDigest(b, "issuing-ca"); err != nil {
		t.Fatalf("B signs with the shared key before revocation: %v", err)
	}
	first, err := revokeKey(a, "issuing-ca", "ceremony-1", "ca_compromise")
	if err != nil {
		t.Fatalf("A RevokeKey: %v", err)
	}
	if err := signDigest(b, "issuing-ca"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("B signs after A revoked the shared key = %v, want FailedPrecondition", err)
	}

	c, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatalf("restart over a keystore holding a revocation: %v", err)
	}
	if err := signDigest(c, "issuing-ca"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restarted signer signs with the revoked key = %v, want FailedPrecondition", err)
	}
	got, err := c.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
	if err != nil || !bytes.Equal(got.GetPublicKey(), pub) || !got.GetRevoked() {
		t.Fatalf("restarted public key = %+v, %v; want the same key reported revoked", got, err)
	}
	again, err := revokeKey(c, "issuing-ca", "ceremony-2", "superseded")
	if err != nil || again.GetOperationId() != first.GetOperationId() || again.GetReason() != "ca_compromise" ||
		again.GetRevokedAtUnix() != first.GetRevokedAtUnix() {
		t.Fatalf("restarted repeat revocation = %+v, %v; want the original %+v", again, err, first)
	}
}

// The control plane revokes through the client over the signer transport and
// reads the revocation back from the signer itself.
func TestClientRevokesAKeyOverTheSignerTransport(t *testing.T) {
	dir, err := os.MkdirTemp("", "rv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(), devServeOptions()) }()
	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	signer, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, "ca-revoked-over-uds")
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := client.KeyRevoked(ctx, "ca-revoked-over-uds"); err != nil || revoked {
		t.Fatalf("fresh key revoked = %v, %v", revoked, err)
	}
	record, pub, err := client.RevokeKey(ctx, "ca-revoked-over-uds", "ceremony-uds", "cessation_of_operation")
	if err != nil || record.OperationID != "ceremony-uds" || record.Reason != "cessation_of_operation" ||
		!bytes.Equal(pub, signer.Public().DER) {
		t.Fatalf("RevokeKey over the transport = %+v, %v", record, err)
	}
	if revoked, err := client.KeyRevoked(ctx, "ca-revoked-over-uds"); err != nil || !revoked {
		t.Fatalf("revoked key read back as revoked = %v, %v", revoked, err)
	}
	if _, err := signer.SignDigest(make([]byte, 32), crypto.SignOptions{Hash: crypto.SHA256}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remote signature with a revoked key = %v, want FailedPrecondition", err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
