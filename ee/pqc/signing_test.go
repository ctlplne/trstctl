// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestSignerPersistsPQCKeysAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	kek, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(kek.Destroy)

	ctx := context.Background()
	digest, err := crypto.Digest(crypto.SHA256, []byte("persistent PQC signer vector"))
	if err != nil {
		t.Fatal(err)
	}
	factory := signing.WithKeyFactory(NewSignerKeyFactory())

	tests := []struct {
		name      string
		handle    string
		proto     signerpb.Algorithm
		algorithm crypto.Algorithm
		verify    func(crypto.PublicKey, []byte, []byte) error
	}{
		{
			name:      "ml-dsa-44",
			handle:    "ml-dsa-root",
			proto:     signerpb.Algorithm_ALGORITHM_LICENSED_1,
			algorithm: MLDSA44,
			verify:    Verify,
		},
		{
			name:      "slh-dsa-sha2-128f",
			handle:    "slh-dsa-root",
			proto:     signerpb.Algorithm_ALGORITHM_LICENSED_5,
			algorithm: SLHDSA128f,
			verify:    VerifySLHDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek), factory)
			if err != nil {
				t.Fatalf("NewPersistentServer (boot 1): %v", err)
			}
			gen, err := s1.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
				Algorithm:   tt.proto,
				RequestedId: tt.handle,
			})
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", tt.algorithm, err)
			}
			if got := gen.GetAlgorithm(); got != tt.proto {
				t.Fatalf("generated algorithm = %v, want %v", got, tt.proto)
			}

			s2, err := signing.NewPersistentServer(signing.NewKeyStore(dir, kek), factory)
			if err != nil {
				t.Fatalf("NewPersistentServer (boot 2): %v", err)
			}
			got, err := s2.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: tt.handle}})
			if err != nil {
				t.Fatalf("GetPublicKey after restart: %v", err)
			}
			if got.GetAlgorithm() != tt.proto {
				t.Fatalf("reloaded algorithm = %v, want %v", got.GetAlgorithm(), tt.proto)
			}
			if !bytes.Equal(got.GetPublicKey(), gen.GetPublicKey()) {
				t.Fatal("PQC public key changed across restart")
			}

			sig, err := s2.Sign(ctx, &signerpb.SignRequest{
				Handle: &signerpb.KeyHandle{Id: tt.handle},
				Digest: digest,
				Hash:   signerpb.Hash_HASH_SHA256,
			})
			if err != nil {
				t.Fatalf("Sign after restart: %v", err)
			}
			pub := crypto.PublicKey{Algorithm: tt.algorithm, DER: got.GetPublicKey()}
			if err := tt.verify(pub, digest, sig.GetSignature()); err != nil {
				t.Fatalf("verify persisted %s signature: %v", tt.algorithm, err)
			}
		})
	}
}
