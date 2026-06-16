package signing_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestServerLifecycle exercises the handlers in-process (the over-UDS path is
// covered separately by TestSignCSROverUDS, where the server runs in a child).
func TestServerLifecycle(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()

	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if gen.GetHandle().GetId() == "" || len(gen.GetPublicKey()) == 0 {
		t.Fatalf("bad GenerateKey response: %+v", gen)
	}

	digest, err := crypto.Digest(crypto.SHA256, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	sresp, err := s.Sign(ctx, &signerpb.SignRequest{
		Handle: gen.GetHandle(),
		Digest: digest,
		Hash:   signerpb.Hash_HASH_SHA256,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub := crypto.PublicKey{Algorithm: crypto.ECDSAP256, DER: gen.GetPublicKey()}
	if err := crypto.VerifyDigest(pub, digest, sresp.GetSignature(), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Errorf("signature from server did not verify: %v", err)
	}

	gp, err := s.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: gen.GetHandle()})
	if err != nil || len(gp.GetPublicKey()) == 0 {
		t.Fatalf("GetPublicKey: %v", err)
	}

	h, err := s.Health(ctx, &signerpb.HealthRequest{})
	if err != nil || h.GetStatus() != signerpb.HealthResponse_STATUS_SERVING {
		t.Fatalf("Health = %v, err %v; want SERVING", h.GetStatus(), err)
	}

	if _, err := s.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: gen.GetHandle()}); err != nil {
		t.Fatalf("DestroyKey: %v", err)
	}
	_, err = s.Sign(ctx, &signerpb.SignRequest{Handle: gen.GetHandle(), Digest: digest, Hash: signerpb.Hash_HASH_SHA256})
	if status.Code(err) != codes.NotFound {
		t.Errorf("Sign after destroy: got %v, want NotFound", status.Code(err))
	}
}

func TestServerRejectsBadRequests(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()

	if _, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_UNSPECIFIED}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("GenerateKey(unspecified): got %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.Sign(ctx, &signerpb.SignRequest{Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Sign(no handle): got %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.Sign(ctx, &signerpb.SignRequest{Handle: &signerpb.KeyHandle{Id: "nope"}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256}); status.Code(err) != codes.NotFound {
		t.Errorf("Sign(unknown handle): got %v, want NotFound", status.Code(err))
	}
	// DestroyKey is idempotent: unknown handle is not an error.
	if _, err := s.DestroyKey(ctx, &signerpb.DestroyKeyRequest{Handle: &signerpb.KeyHandle{Id: "nope"}}); err != nil {
		t.Errorf("DestroyKey(unknown) should be idempotent, got %v", err)
	}
}

func TestServerShutdownZeroizes(t *testing.T) {
	s := signing.NewServer()
	ctx := context.Background()
	gen, err := s.GenerateKey(ctx, &signerpb.GenerateKeyRequest{Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256})
	if err != nil {
		t.Fatal(err)
	}
	s.Shutdown()
	if _, err := s.Sign(ctx, &signerpb.SignRequest{Handle: gen.GetHandle(), Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256}); status.Code(err) != codes.NotFound {
		t.Errorf("Sign after shutdown: got %v, want NotFound", status.Code(err))
	}
	h, _ := s.Health(ctx, &signerpb.HealthRequest{})
	if h.GetStatus() != signerpb.HealthResponse_STATUS_DRAINING {
		t.Errorf("Health after shutdown = %v, want DRAINING", h.GetStatus())
	}
}
