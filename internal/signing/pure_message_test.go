// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A classical key cannot honor a pure-message request: it would sign
// arbitrary bytes as if they were a digest, so the real server handler refuses
// with INVALID_ARGUMENT and signs nothing. (The post-quantum acceptance lives
// in internal/pqc, which owns the ML-DSA key factory.)
func TestSignRefusesPureMessageOnClassicalKey(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()
	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "classical-ca",
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = s.Sign(ctx, &signerpb.SignRequest{
		Handle: gen.GetHandle(), Digest: make([]byte, 1024), Hash: signerpb.Hash_HASH_NONE,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("pure-message sign on an ECDSA key = %v, want INVALID_ARGUMENT", err)
	}
	// The hashed form still works for the same key.
	if _, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle: gen.GetHandle(), Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
	}); err != nil {
		t.Fatalf("digest sign on the same key: %v", err)
	}
}
