// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"errors"
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

type fakeKEMCustody struct {
	generatedHandle string
	generatedAlg    signerpb.Algorithm
	decapHandle     string
	decapCiphertext []byte
	zeroizedHandle  string
	destroyed       bool
	failGenerate    error
	failDecap       error
	failZeroize     error
}

func (f *fakeKEMCustody) GenerateSuccessorKEM(_ context.Context, handle string, alg signerpb.Algorithm) (signerpb.Algorithm, []byte, error) {
	if f.failGenerate != nil {
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED, nil, f.failGenerate
	}
	f.generatedHandle = handle
	f.generatedAlg = alg
	return alg, []byte("kem-public:" + handle), nil
}

func (f *fakeKEMCustody) Decapsulate(_ context.Context, handle string, ciphertext []byte) ([]byte, error) {
	if f.failDecap != nil {
		return nil, f.failDecap
	}
	f.decapHandle = handle
	f.decapCiphertext = append([]byte(nil), ciphertext...)
	return []byte("shared:" + handle + ":" + string(ciphertext)), nil
}

func (f *fakeKEMCustody) ZeroizeKey(_ context.Context, handle string) error {
	if f.failZeroize != nil {
		return f.failZeroize
	}
	f.zeroizedHandle = handle
	return nil
}

func (f *fakeKEMCustody) DestroyAll() { f.destroyed = true }

func TestServerKEMCustodyHandlers(t *testing.T) {
	ctx := context.Background()
	custody := &fakeKEMCustody{}
	s := signing.NewServer(signing.WithKEMCustody(custody))

	pub, err := s.GenerateSuccessorKEM(ctx, &signerpb.GenerateSuccessorKEMRequest{
		Handle:    "kem-1",
		Algorithm: signerpb.Algorithm_ALGORITHM_LICENSED_1,
	})
	if err != nil {
		t.Fatalf("GenerateSuccessorKEM: %v", err)
	}
	if pub.GetHandle() != "kem-1" || pub.GetAlgorithm() != signerpb.Algorithm_ALGORITHM_LICENSED_1 || !bytes.Equal(pub.GetPublicKey(), []byte("kem-public:kem-1")) {
		t.Fatalf("bad KEM public response: %+v", pub)
	}
	if custody.generatedHandle != "kem-1" || custody.generatedAlg != signerpb.Algorithm_ALGORITHM_LICENSED_1 {
		t.Fatalf("custody generate saw handle=%q alg=%v", custody.generatedHandle, custody.generatedAlg)
	}

	ss, err := s.Decapsulate(ctx, &signerpb.DecapsulateRequest{Handle: "kem-1", Ciphertext: []byte("ct")})
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss.GetSharedSecret(), []byte("shared:kem-1:ct")) {
		t.Fatalf("shared secret = %q", ss.GetSharedSecret())
	}
	if custody.decapHandle != "kem-1" || !bytes.Equal(custody.decapCiphertext, []byte("ct")) {
		t.Fatalf("custody decap saw handle=%q ciphertext=%q", custody.decapHandle, custody.decapCiphertext)
	}

	if _, err := s.ZeroizeKey(ctx, &signerpb.ZeroizeKeyRequest{Handle: "kem-1"}); err != nil {
		t.Fatalf("ZeroizeKey: %v", err)
	}
	if custody.zeroizedHandle != "kem-1" {
		t.Fatalf("custody zeroized %q, want kem-1", custody.zeroizedHandle)
	}
	s.Shutdown()
	if !custody.destroyed {
		t.Fatal("Shutdown did not destroy KEM custody")
	}
}

func TestServerKEMCustodyRejectsBadRequestsAndMissingCustody(t *testing.T) {
	ctx := context.Background()
	s := signing.NewServer()

	if _, err := s.GenerateSuccessorKEM(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("GenerateSuccessorKEM(nil) = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.GenerateSuccessorKEM(ctx, &signerpb.GenerateSuccessorKEMRequest{Handle: "kem"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("GenerateSuccessorKEM(no alg) = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.GenerateSuccessorKEM(ctx, &signerpb.GenerateSuccessorKEMRequest{Handle: "kem", Algorithm: signerpb.Algorithm_ALGORITHM_LICENSED_1}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("GenerateSuccessorKEM(no custody) = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.Decapsulate(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Decapsulate(nil) = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.Decapsulate(ctx, &signerpb.DecapsulateRequest{Handle: "kem"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Decapsulate(no ciphertext) = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := s.Decapsulate(ctx, &signerpb.DecapsulateRequest{Handle: "kem", Ciphertext: []byte("ct")}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Decapsulate(no custody) = %v, want Unimplemented", status.Code(err))
	}
	if _, err := s.ZeroizeKey(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ZeroizeKey(nil) = %v, want InvalidArgument", status.Code(err))
	}

	fail := signing.NewServer(signing.WithKEMCustody(&fakeKEMCustody{
		failGenerate: errors.New("generate denied"),
		failDecap:    errors.New("decap denied"),
		failZeroize:  errors.New("zeroize denied"),
	}))
	if _, err := fail.GenerateSuccessorKEM(ctx, &signerpb.GenerateSuccessorKEMRequest{Handle: "kem", Algorithm: signerpb.Algorithm_ALGORITHM_LICENSED_1}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("GenerateSuccessorKEM(failing custody) = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := fail.Decapsulate(ctx, &signerpb.DecapsulateRequest{Handle: "kem", Ciphertext: []byte("ct")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Decapsulate(failing custody) = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := fail.ZeroizeKey(ctx, &signerpb.ZeroizeKeyRequest{Handle: "kem"}); status.Code(err) != codes.Internal {
		t.Fatalf("ZeroizeKey(failing custody) = %v, want Internal", status.Code(err))
	}
}

func TestClientKEMCustodyRPCs(t *testing.T) {
	dir, err := os.MkdirTemp("", "kem-rpc")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	custody := &fakeKEMCustody{}
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(signing.WithKEMCustody(custody)), devServeOptions())
	}()

	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()
	if got := (signing.StaticProvider{C: client}).Client(); got != client {
		t.Fatal("static provider did not return the wrapped client")
	}

	created, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, "signing-rpc")
	if err != nil {
		t.Fatalf("client GenerateKeyHandle: %v", err)
	}
	bound, err := client.SignerForHandle(ctx, "signing-rpc")
	if err != nil {
		t.Fatalf("client SignerForHandle: %v", err)
	}
	if created.Algorithm() != crypto.ECDSAP256 || bound.Algorithm() != crypto.ECDSAP256 {
		t.Fatalf("remote signer algorithms = %s/%s, want ECDSA-P256", created.Algorithm(), bound.Algorithm())
	}
	if bound.Purpose() != signing.PurposeGeneric {
		t.Fatalf("bound signer purpose = %v, want generic", bound.Purpose())
	}

	pub, err := client.GenerateSuccessorKEM(ctx, "kem-rpc", signerpb.Algorithm_ALGORITHM_LICENSED_1)
	if err != nil {
		t.Fatalf("client GenerateSuccessorKEM: %v", err)
	}
	if pub.Handle != "kem-rpc" || pub.Algorithm != signerpb.Algorithm_ALGORITHM_LICENSED_1 || !bytes.Equal(pub.PublicDER, []byte("kem-public:kem-rpc")) {
		t.Fatalf("bad client KEM public result: %+v", pub)
	}
	ss, err := client.Decapsulate(ctx, "kem-rpc", []byte("ciphertext"))
	if err != nil {
		t.Fatalf("client Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, []byte("shared:kem-rpc:ciphertext")) {
		t.Fatalf("client shared secret = %q", ss)
	}
	if err := client.ZeroizeKey(ctx, "kem-rpc"); err != nil {
		t.Fatalf("client ZeroizeKey: %v", err)
	}
	if custody.zeroizedHandle != "kem-rpc" {
		t.Fatalf("custody zeroized %q, want kem-rpc", custody.zeroizedHandle)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeServerWithOptions: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("KEM RPC server did not stop")
	}
	if !custody.destroyed {
		t.Fatal("served shutdown did not destroy KEM custody")
	}
}
