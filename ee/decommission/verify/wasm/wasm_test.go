// SPDX-License-Identifier: LicenseRef-trstctl-EE

package wasm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	vdecverify "trstctl.com/trstctl/ee/decommission/verify"
	"trstctl.com/trstctl/internal/crypto"
)

// Guard for VDEC-claim-24: the stored-instruction verifier reaches the same
// verdict as the Go verifier on the published vectors.
func TestVerifyJSON_VerdictParity(t *testing.T) {
	minter, err := record.NewMinter(record.Config{
		SignerID:  "test-vdec-wasm-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000900, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)

	proofNode, err := vdecverify.EncodeProofNode(vdecverify.ProofRight, crypto.SHA256Sum([]byte("wasm-proof-node")))
	if err != nil {
		t.Fatalf("EncodeProofNode: %v", err)
	}
	rec, err := minter.Mint(context.Background(), record.MintRequest{
		TenantID:               "tenant-a",
		StableKeyID:            "key://tenant-a/root-ca",
		FinalEpoch:             9,
		CompletionEventsDigest: crypto.SHA256Sum([]byte("completion-events")),
		DestructionEvidence: record.EvidenceFromDestruction(gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           "tenant-a",
			StableKeyID:        "key://tenant-a/root-ca",
			FinalEpoch:         9,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("hsm destroy attestation statement"),
			Digest:             crypto.SHA256Sum([]byte("destroy evidence")),
		}),
		AuditChainHead:             "audit-head-after-destruction",
		TransparencyLogID:          "vdec-transparency-log",
		TransparencyInclusionProof: [][]byte{proofNode},
		TransparencyTreeSize:       2,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	head, err := vdecverify.HeadForRecord(rec)
	if err != nil {
		t.Fatalf("HeadForRecord: %v", err)
	}
	req := vdecverify.Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        vdecverify.RetainedEpoch{StableKeyID: rec.Commitment.StableKeyID, Epoch: 9},
	}
	want, err := vdecverify.Verify(req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	out, err := VerifyJSON(raw)
	if err != nil {
		t.Fatalf("VerifyJSON: %v", err)
	}
	var got Response
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if !got.OK || got.Verdict.Determination != want.Determination || got.Verdict.StableKeyID != want.StableKeyID || got.Verdict.FinalEpoch != want.FinalEpoch {
		t.Fatalf("VerifyJSON response = %+v, want verdict parity with %+v", got, want)
	}
}
