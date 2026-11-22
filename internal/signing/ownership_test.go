// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestCR011TenantCAOwnershipSurvivesSignerRestart(t *testing.T) {
	const (
		owner    = "11111111-1111-1111-1111-111111111111"
		neighbor = "22222222-2222-2222-2222-222222222222"
		handle   = "ca-hierarchy-cr011-owner"
	)
	rawKEK, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(rawKEK)
	secret.Wipe(rawKEK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	authSecret := bytes.Repeat([]byte{0x51}, 32)
	authz, err := crypto.NewSignAuthorizer(authSecret)
	secret.Wipe(authSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	keyDir := filepath.Join(t.TempDir(), "keys")
	open := func() *Server {
		t.Helper()
		s, err := NewPersistentServer(NewKeyStore(keyDir, kek), WithAuthorizer(authz))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	owned := metadata.NewIncomingContext(context.Background(), metadata.Pairs(mdRequireAuth, "1", mdKeyOwnerTenant, owner, mdKeyClass, KeyClassTenantCA))
	s1 := open()
	created, err := s1.GenerateKey(owned, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: handle,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the signer from its sealed key file. The same owner succeeds;
	// another tenant and a key from a reserved namespace stay unavailable.
	s2 := open()
	lookup := func(ctx context.Context, id string) ([]byte, error) {
		t.Helper()
		resp, err := s2.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: id}})
		if err != nil {
			return nil, err
		}
		return resp.GetPublicKey(), nil
	}
	got, err := lookup(owned, handle)
	if err != nil || !bytes.Equal(got, created.GetPublicKey()) {
		t.Fatalf("owner readback after restart = %v, public key retained=%t", err, bytes.Equal(got, created.GetPublicKey()))
	}
	other := metadata.NewIncomingContext(context.Background(), metadata.Pairs(mdKeyOwnerTenant, neighbor, mdKeyClass, KeyClassTenantCA))
	if _, err := lookup(other, handle); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("neighbor readback = %v; want PermissionDenied", err)
	}
	for _, reserved := range []string{"issuing-ca", "agent-ca", "pcas:tenant-root:v1:abc", "agid-issuing-ca-" + owner} {
		_, err := s2.GenerateKey(owned, &signerpb.GenerateKeyRequest{
			Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: reserved,
			AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_CA_SIGN},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("tenant CA under reserved handle %q = %v; want PermissionDenied", reserved, err)
		}
	}
}
