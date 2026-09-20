// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type fakeArtifactSigner struct {
	got signing.ArtifactSignRequest
}

func (f *fakeArtifactSigner) SignArtifact(_ context.Context, req signing.ArtifactSignRequest) (signing.ArtifactSignature, error) {
	f.got = req
	return signing.ArtifactSignature{
		KeyID:        req.KeyID,
		Algorithm:    crypto.ECDSAP256,
		PublicKeyDER: []byte("public"),
		Signature:    []byte("signature"),
	}, nil
}

func TestSignArtifactFailsClosedWithoutAttachedSigner(t *testing.T) {
	s := signing.NewServer()
	_, err := s.SignArtifact(context.Background(), &signerpb.SignArtifactRequest{
		Kind:        "artifact",
		TenantId:    "tenant-1",
		AuthorityId: "authority-1",
		KeyId:       "key-1",
		Payload:     []byte("payload"),
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("SignArtifact without attachment: got %v, want Unimplemented", status.Code(err))
	}
}

func TestSignArtifactDispatchesToAttachedSigner(t *testing.T) {
	attached := &fakeArtifactSigner{}
	s := signing.NewServer(signing.WithArtifactSigner(attached))
	resp, err := s.SignArtifact(context.Background(), &signerpb.SignArtifactRequest{
		Kind:        "artifact",
		TenantId:    "tenant-1",
		AuthorityId: "authority-1",
		KeyId:       "key-1",
		Payload:     []byte("payload"),
	})
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	if attached.got.Kind != "artifact" || attached.got.TenantID != "tenant-1" || attached.got.AuthorityID != "authority-1" || attached.got.KeyID != "key-1" {
		t.Fatalf("attached signer saw wrong request: %+v", attached.got)
	}
	if !bytes.Equal(attached.got.Payload, []byte("payload")) {
		t.Fatalf("attached signer payload = %q, want payload", attached.got.Payload)
	}
	if resp.GetKeyId() != "key-1" || resp.GetAlgorithm() != signerpb.Algorithm_ALGORITHM_ECDSA_P256 || !bytes.Equal(resp.GetPublicKey(), []byte("public")) || !bytes.Equal(resp.GetSignature(), []byte("signature")) {
		t.Fatalf("unexpected artifact response: %+v", resp)
	}
}
