// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestINT07_SuccessorKeyIsLockedAndZeroizable pins claim 16 on the succession path: a
// successor key generated INSIDE the signer (GenerateSuccessorKey, the INT-03 custody
// path) is held as a crypto.LockedSigner — mlock + MADV_DONTDUMP + zeroize-on-Destroy
// (AN-8) — signs as a real key, and is removed and destroyed via the DestroyKey RPC.
// The mlock/zeroize semantics themselves are covered by internal/crypto's LockedSigner
// tests; this pins that the SUCCESSION path uses that locked custody, not a plain
// in-heap key. The signer process additionally hardens itself (PR_SET_DUMPABLE=0,
// RLIMIT_CORE=0) via Harden().
func TestINT07_SuccessorKeyIsLockedAndZeroizable(t *testing.T) {
	s := NewServer()

	signer, err := s.GenerateSuccessorKey("succ-h", crypto.ECDSAP384)
	if err != nil {
		t.Fatalf("generate successor: %v", err)
	}

	// The successor is a usable key.
	sig, err := signer.Sign([]byte("commitment"), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil || len(sig) == 0 {
		t.Fatalf("successor sign: %v", err)
	}
	if err := crypto.VerifyMessage(signer.Public().DER, []byte("commitment"), sig); err != nil {
		t.Fatalf("successor signature does not verify: %v", err)
	}

	// Claim 16: it is held as a LOCKED, zeroizable buffer inside the signer.
	s.mu.Lock()
	held, ok := s.keys["succ-h"]
	s.mu.Unlock()
	if !ok {
		t.Fatal("successor key is not held in the signer keystore")
	}
	if _, locked := held.signer.(*crypto.LockedSigner); !locked {
		t.Fatalf("successor key type = %T, want *crypto.LockedSigner (mlock'd/zeroized on Destroy)", held.signer)
	}

	// It is zeroized/removed via the DestroyKey RPC path.
	if _, err := s.DestroyKey(context.Background(), &signerpb.DestroyKeyRequest{Handle: &signerpb.KeyHandle{Id: "succ-h"}}); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	s.mu.Lock()
	_, still := s.keys["succ-h"]
	s.mu.Unlock()
	if still {
		t.Fatal("successor key still held after DestroyKey (not zeroized)")
	}
}

// TestINT07_NoSuccessorKeyExportOverTransport pins the non-release property (claims
// 12/16/26): the signer's wire contract exposes no operation that returns a key's
// private bytes. Private material leaves the signer only sealed-at-rest under a KEK
// (the SealedBytes path), never in the clear over the transport. The check reflects
// the generated client interface — the complete set of operations a control plane can
// invoke — and fails if any method name suggests private-key export.
func TestINT07_NoSuccessorKeyExportOverTransport(t *testing.T) {
	typ := reflect.TypeOf((*signerpb.SignerServiceClient)(nil)).Elem()
	for i := 0; i < typ.NumMethod(); i++ {
		name := strings.ToLower(typ.Method(i).Name)
		for _, forbidden := range []string{"export", "private", "reveal", "extract", "unwrap", "unseal"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("signer wire contract exposes %q — a key-export surface is forbidden (non-release, claims 12/16/26)", typ.Method(i).Name)
			}
		}
	}
}
