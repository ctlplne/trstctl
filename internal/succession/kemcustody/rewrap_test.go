// SPDX-License-Identifier: BUSL-1.1

package kemcustody

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A re-wrap inside custody moves a data key from the predecessor KEM key to the
// successor: the successor envelope opens under the successor key alone to the
// same data key digest, the predecessor key can no longer open it, and a
// tampered or re-bound envelope is refused.
func TestStoreRewrapsDataKeyBetweenHeldKeys(t *testing.T) {
	ctx := context.Background()
	s, err := NewStore("", nil)
	if err != nil {
		t.Fatal(err)
	}
	alg := pqc.KEMAlgorithmToProto(crypto.Algorithm("ML-KEM-768"))
	if alg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		t.Fatal("ML-KEM-768 has no proto algorithm")
	}
	_, predPub, err := s.GenerateSuccessorKEM(ctx, "t:id:kem:1", alg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GenerateSuccessorKEM(ctx, "t:id:kem:2", alg); err != nil {
		t.Fatal(err)
	}
	dek := []byte("the-data-key-protecting-a-backup")
	predAAD := []byte("trstctl/pcas/kem-data-key/v1|id|1|backup:a")
	succAAD := []byte("trstctl/pcas/kem-data-key/v1|id|2|backup:a")
	ct, ss, err := pqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm("ML-KEM-768"), DER: predPub})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.KEMDataKeySeal(ss, dek, predAAD)
	if err != nil {
		t.Fatal(err)
	}
	want := crypto.SHA256Sum(dek)

	ct2, wrapped2, digest, err := s.RewrapDataKey(ctx, "t:id:kem:1", "t:id:kem:2", ct, wrapped, predAAD, succAAD)
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if !bytes.Equal(digest, want) || bytes.Equal(ct2, ct) || bytes.Equal(wrapped2, wrapped) {
		t.Fatalf("rewrap result digest=%x (want %x) ct-same=%v wrapped-same=%v", digest, want, bytes.Equal(ct2, ct), bytes.Equal(wrapped2, wrapped))
	}
	readback, err := s.VerifyDataKey(ctx, "t:id:kem:2", ct2, wrapped2, succAAD)
	if err != nil || !bytes.Equal(readback, want) {
		t.Fatalf("readback under successor: %v %x", err, readback)
	}
	if _, err := s.VerifyDataKey(ctx, "t:id:kem:1", ct2, wrapped2, succAAD); err == nil {
		t.Fatal("the predecessor key opened the successor envelope")
	}
	if _, err := s.VerifyDataKey(ctx, "t:id:kem:2", ct2, wrapped2, predAAD); err == nil {
		t.Fatal("the successor envelope opened under the predecessor binding")
	}
	tampered := append([]byte(nil), wrapped2...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := s.VerifyDataKey(ctx, "t:id:kem:2", ct2, tampered, succAAD); err == nil {
		t.Fatal("a tampered envelope opened")
	}
	if _, _, _, err := s.RewrapDataKey(ctx, "t:id:kem:1", "t:id:kem:1", ct, wrapped, predAAD, succAAD); err == nil {
		t.Fatal("a re-wrap onto the same key was accepted")
	}
	if _, _, _, err := s.RewrapDataKey(ctx, "t:id:kem:1", "t:id:kem:9", ct, wrapped, predAAD, succAAD); err == nil {
		t.Fatal("a re-wrap to an unknown successor handle was accepted")
	}
}
