// SPDX-License-Identifier: BUSL-1.1

package translog

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestProof_RealVerifierRoundTrip proves the self-contained inclusion proof verifies
// under the log's signed head and rejects forgeries — the real Merkle check that
// replaces the injected closure (INT-18).
func TestProof_RealVerifierRoundTrip(t *testing.T) {
	be := crypto.NewSoftwareBackend()
	logKey, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	l := New(logKey)
	leaves := [][]byte{[]byte("rec-0"), []byte("rec-1"), []byte("rec-2"), []byte("rec-3"), []byte("rec-4")}
	for _, e := range leaves {
		if _, _, err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	// A real proof for leaf 2 round-trips through encode/decode and verifies under the
	// log's public key.
	p, err := l.Prove(2)
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeProof(p)
	dec, err := DecodeProof(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := VerifyLeafInclusion(leaves[2], dec, logKey.Public().DER); err != nil {
		t.Fatalf("real proof rejected: %v", err)
	}
	if err := VerifyEncodedInclusion(leaves[2], enc, logKey.Public().DER); err != nil {
		t.Fatalf("encoded-form verify rejected: %v", err)
	}

	// Wrong leaf under a valid, signed head -> not included.
	if err := VerifyLeafInclusion([]byte("rec-forged"), dec, logKey.Public().DER); !errors.Is(err, ErrProofInclusion) {
		t.Fatalf("wrong leaf: got %v, want ErrProofInclusion", err)
	}

	// No trusted log key -> fail closed (cannot soundly check inclusion).
	if err := VerifyLeafInclusion(leaves[2], dec, nil); !errors.Is(err, ErrProofUntrusted) {
		t.Fatalf("no STH key: got %v, want ErrProofUntrusted", err)
	}

	// Tampered STH (root flipped) -> signature no longer verifies.
	bad := dec
	bad.STH.RootHash = append([]byte{bad.STH.RootHash[0] ^ 0xff}, bad.STH.RootHash[1:]...)
	if err := VerifyLeafInclusion(leaves[2], bad, logKey.Public().DER); !errors.Is(err, ErrProofSTH) {
		t.Fatalf("tampered STH: got %v, want ErrProofSTH", err)
	}

	// Wrong log key -> STH signature invalid.
	other, _ := be.GenerateKey(crypto.ECDSAP256)
	if err := VerifyLeafInclusion(leaves[2], dec, other.Public().DER); !errors.Is(err, ErrProofSTH) {
		t.Fatalf("wrong log key: got %v, want ErrProofSTH", err)
	}

	// Malformed bytes -> decode error, not a panic or false accept.
	if _, err := DecodeProof([]byte("not a proof")); !errors.Is(err, ErrProofMalformed) {
		t.Fatalf("malformed decode: got %v, want ErrProofMalformed", err)
	}
	if _, err := DecodeProof(append(enc, 0x00)); !errors.Is(err, ErrProofMalformed) {
		t.Fatalf("trailing-byte decode: got %v, want ErrProofMalformed", err)
	}
}
