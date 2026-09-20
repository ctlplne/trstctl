// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"

	"trstctl.com/trstctl/internal/signing"
)

// TestGate_FreeSingleHopApproved proves the free single-hop path stays free: a request
// asserting NO delegation preconditions, NO attestation, and NO agent-stack subject is
// approved with an empty binding (the control plane owns license/policy gating, AGID-07),
// so replacing the 04a passthrough with the real 04b verifier does NOT gate the free
// path. The signer's own key-op path mints it.
func TestGate_FreeSingleHopApproved(t *testing.T) {
	f := newGateFixture(t, map[string]RootAnchor{}, nil, nil, nil)
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "single-hop-subject"}
	dec, err := f.gate.VerifyIssuancePreconditions(backgroundCtx(), req)
	if err != nil {
		t.Fatalf("free single-hop returned error: %v", err)
	}
	if !dec.Approved {
		t.Fatalf("free single-hop refused: %s", refusalReason(t, dec))
	}
	if len(dec.BindingMaterial) != 0 {
		t.Fatalf("free single-hop carried binding material %q, want empty", dec.BindingMaterial)
	}
	if len(dec.RefusalRecord) != 0 {
		t.Fatal("free single-hop produced a refusal record")
	}
}

// TestGate_UndecodableBodyRefusesFailClosed proves an undecodable precondition body is a
// fail-closed refusal (NOT the free path and NOT an error): garbage over the seam yields a
// signed refusal naming the decode check, with zero key ops.
func TestGate_UndecodableBodyRefusesFailClosed(t *testing.T) {
	f := newGateFixture(t, map[string]RootAnchor{}, nil, nil, nil)
	req := signing.IssuancePreconditions{
		TenantID:       "t1",
		TrustAnchorRef: "subj",
		Preconditions:  []byte(`{"chain": this-is-not-valid-json`),
	}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("undecodable body approved (must fail closed)")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("undecodable body performed %d key ops, want zero", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckDecode {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckDecode)
	}
	if err := VerifyRefusal(f.refusalPub, art); err != nil {
		t.Fatalf("signed refusal does not verify: %v", err)
	}
}

// TestGate_ConstructorFailsClosed proves NewGate rejects a configuration that cannot fail
// closed (no trust store, no refusal signer, no revocation reader).
func TestGate_ConstructorFailsClosed(t *testing.T) {
	refusal, _ := signerWithDER(t)
	if _, err := NewGate(Config{RefusalSigner: refusal, Revocations: NeverRevoked{}}); err != ErrNoTrustStore {
		t.Fatalf("no trust store: err = %v, want ErrNoTrustStore", err)
	}
	if _, err := NewGate(Config{Roots: NewTrustStore(nil), Revocations: NeverRevoked{}}); err != ErrNoRefusalSigner {
		t.Fatalf("no refusal signer: err = %v, want ErrNoRefusalSigner", err)
	}
	if _, err := NewGate(Config{Roots: NewTrustStore(nil), RefusalSigner: refusal}); err != ErrNoRevocationReader {
		t.Fatalf("no revocation reader: err = %v, want ErrNoRevocationReader", err)
	}
}
