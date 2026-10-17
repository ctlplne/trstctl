// SPDX-License-Identifier: BUSL-1.1

package kemcustody

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A worker can lose the response after the signer has persisted a successor.
// The same tenant-bound handle and algorithm must return the original public
// key, including after a signer restart; a different algorithm must not reuse
// that key under a misleading algorithm label.
func TestGenerateSuccessorKEMRecoversLostResponseAcrossRestart(t *testing.T) {
	ctx := context.Background()
	wrapper, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	dir := t.TempDir()
	first, err := NewStore(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	const handle = "qa-tenant-identity-kem-1"
	const alg = signerpb.Algorithm_ALGORITHM_LICENSED_2
	gotAlg, pub, err := first.GenerateSuccessorKEM(ctx, handle, alg)
	if err != nil || gotAlg != alg || len(pub) == 0 {
		t.Fatalf("initial KEM successor generation: algorithm=%v public_len=%d err=%v", gotAlg, len(pub), err)
	}
	gotAlg, replayPub, err := first.GenerateSuccessorKEM(ctx, handle, alg)
	if err != nil || gotAlg != alg || !bytes.Equal(pub, replayPub) {
		t.Fatalf("same-process lost-response replay: algorithm=%v same_public=%t err=%v", gotAlg, bytes.Equal(pub, replayPub), err)
	}
	first.DestroyAll()
	restarted, err := NewStore(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.DestroyAll()
	gotAlg, replayPub, err = restarted.GenerateSuccessorKEM(ctx, handle, alg)
	if err != nil || gotAlg != alg || !bytes.Equal(pub, replayPub) {
		t.Fatalf("post-restart lost-response replay: algorithm=%v same_public=%t err=%v", gotAlg, bytes.Equal(pub, replayPub), err)
	}
	ct, wantShared, err := pqc.Encapsulate(crypto.PublicKey{Algorithm: pqc.MLKEM768, DER: pub})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(wantShared)
	gotShared, err := restarted.Decapsulate(ctx, handle, ct)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(gotShared)
	if !bytes.Equal(gotShared, wantShared) {
		t.Fatal("replayed public key does not decapsulate through the restarted signer custody")
	}
	if _, _, err := restarted.GenerateSuccessorKEM(ctx, handle, signerpb.Algorithm_ALGORITHM_LICENSED_1); err == nil {
		t.Fatal("same KEM handle accepted a different algorithm")
	}
}

// TestAlgorithmByte pins the sealed-record algorithm header encoding against
// hand-written literals. Expected values are written out by hand rather than
// derived from a conversion so the test is an independent oracle.
func TestAlgorithmByte(t *testing.T) {
	cases := []struct {
		name    string
		in      signerpb.Algorithm
		want    byte
		wantErr bool
	}{
		{name: "unspecified", in: signerpb.Algorithm(0), want: 0},
		{name: "one", in: signerpb.Algorithm(1), want: 1},
		{name: "licensed7", in: signerpb.Algorithm(13), want: 13},
		{name: "max_byte_minus_one", in: signerpb.Algorithm(254), want: 254},
		{name: "max_byte", in: signerpb.Algorithm(255), want: 255},
		{name: "just_past_max_byte", in: signerpb.Algorithm(256), wantErr: true},
		{name: "negative_one", in: signerpb.Algorithm(-1), wantErr: true},
		{name: "max_int32", in: signerpb.Algorithm(2147483647), wantErr: true},
		{name: "min_int32", in: signerpb.Algorithm(-2147483648), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algorithmByte(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("algorithmByte(%d) = %d, want error", int32(tc.in), got)
				}
				if got != 0 {
					t.Fatalf("algorithmByte(%d) returned %d on error, want 0", int32(tc.in), got)
				}
				return
			}
			if err != nil {
				t.Fatalf("algorithmByte(%d) unexpected error: %v", int32(tc.in), err)
			}
			if got != tc.want {
				t.Fatalf("algorithmByte(%d) = %d, want %d", int32(tc.in), got, tc.want)
			}
		})
	}
}

// TestAlgorithmByteRoundTripsLoadPath checks that every algorithm the enum
// actually defines survives the save-side narrowing and the load-side widening
// unchanged, which is the property loadLocked depends on.
func TestAlgorithmByteRoundTripsLoadPath(t *testing.T) {
	for v := int32(0); v <= 13; v++ {
		alg := signerpb.Algorithm(v)
		b, err := algorithmByte(alg)
		if err != nil {
			t.Fatalf("algorithmByte(%d) unexpected error: %v", v, err)
		}
		if back := signerpb.Algorithm(b); back != alg {
			t.Fatalf("round trip of %d produced %d", v, int32(back))
		}
	}
}
