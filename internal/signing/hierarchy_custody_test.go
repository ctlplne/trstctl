// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestPersistentHierarchySlotHasOneCanonicalOwner(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK(t)
	first, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Shutdown)
	second, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Shutdown)
	ctx := context.Background()
	const handle = "ca-hierarchy-11111111-1111-4111-8111-111111111111"
	create := func(s *signing.Server, id string) (*signerpb.GenerateKeyResponse, error) {
		return s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
			Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: id,
		})
	}
	if _, err := create(second, strings.ToUpper(handle)); status.Code(err) != codes.InvalidArgument {
		t.Errorf("noncanonical hierarchy handle status = %v, want InvalidArgument", status.Code(err))
	}
	original, err := create(first, handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := create(second, handle); status.Code(err) != codes.AlreadyExists {
		t.Errorf("second hierarchy key status = %v, want AlreadyExists", status.Code(err))
	}
	loaded, err := second.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: original.Handle})
	if err != nil || !bytes.Equal(loaded.GetPublicKey(), original.PublicKey) {
		t.Fatal("the second replica did not load the original public key", err)
	}
}
