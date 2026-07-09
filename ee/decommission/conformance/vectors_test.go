// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	vdecverify "trstctl.com/trstctl/ee/decommission/verify"
	vdecwasm "trstctl.com/trstctl/ee/decommission/verify/wasm"
	"trstctl.com/trstctl/internal/crypto"
)

const vectorPath = "testdata/vectors/destruction-record-v1.json"

type destructionRecordVector struct {
	Version               int                           `json:"version"`
	Description           string                        `json:"description"`
	Vector                record.PublishedVector        `json:"vector"`
	Request               vdecverify.Request            `json:"request"`
	ExpectedDetermination string                        `json:"expected_determination"`
	Completion            vdecverify.CompletionEvidence `json:"completion"`
}

func loadVectors(t *testing.T) []destructionRecordVector {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read %s (run UPDATE_VDEC_VECTORS=1 go test ./ee/decommission/conformance): %v", vectorPath, err)
	}
	var v destructionRecordVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", vectorPath, err)
	}
	return []destructionRecordVector{v}
}

func writeVector(t *testing.T) {
	t.Helper()
	v := buildVector(t)
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal vector: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildVector(t *testing.T) destructionRecordVector {
	t.Helper()
	tenantID := "77777777-7777-7777-7777-777777777777"
	stableKeyID := "key://tenant-wire/root-ca"
	finalEpoch := uint64(7)
	registered := []depstate.Dependent{
		{Class: depstate.DependentCiphertext, ID: "ct-live-1"},
		{Class: depstate.DependentWrappedKey, ID: "wrapped-dek-1"},
		{Class: depstate.DependentCredential, ID: "cred-retired-1"},
		{Class: depstate.DependentLeasedSecret, ID: "lease-db-1"},
		{Class: depstate.DependentDataSet, ID: "dataset-erasure-1"},
	}
	completion := vdecverify.CompletionEvidence{
		Registered: registered,
		Completed:  registered[:2],
		Released:   []depstate.Dependent{registered[2]},
		Erased:     registered[3:],
	}
	completionDigest, err := vdecverify.CompletionEventsDigest(tenantID, stableKeyID, finalEpoch, completion)
	if err != nil {
		t.Fatalf("CompletionEventsDigest: %v", err)
	}
	minter, err := record.NewMinter(record.Config{
		SignerID:  "test-vdec-conformance-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800001100, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)
	successor, err := crypto.GenerateLockedKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatalf("GenerateLockedKey successor: %v", err)
	}
	defer successor.Destroy()
	proofNode, err := vdecverify.EncodeProofNode(vdecverify.ProofRight, crypto.SHA256Sum([]byte("vdec-conformance-proof-sibling")))
	if err != nil {
		t.Fatalf("EncodeProofNode: %v", err)
	}
	destroyEvidence := gate.DestructionEvidence{
		Kind:               gate.TypeCustodyHSMDestroyed,
		TenantID:           tenantID,
		StableKeyID:        stableKeyID,
		FinalEpoch:         finalEpoch,
		AttestationClass:   gate.ClassCertifiedHardware,
		AttestationClassID: gate.ClassCertifiedHardware.ID(),
		Record:             []byte("module-signed destroy attestation for vdec conformance vector"),
		Digest:             crypto.SHA256Sum([]byte("destroy evidence vdec conformance vector")),
	}
	rec, err := minter.Mint(context.Background(), record.MintRequest{
		TenantID:                    tenantID,
		StableKeyID:                 stableKeyID,
		FinalEpoch:                  finalEpoch,
		CompletionEventsDigest:      completionDigest,
		RequiredSetDigest:           crypto.SHA256Sum([]byte("vdec conformance required set")),
		DestructionEvidence:         record.EvidenceFromDestruction(destroyEvidence),
		AuditChainHead:              "audit-head-after-vdec-conformance-destroy",
		Successors:                  []record.SuccessorKey{{ID: "key://tenant-wire/root-ca-successor", Epoch: finalEpoch + 1, Algorithm: successor.Public().Algorithm, PublicDER: successor.Public().DER}},
		PolicyRef:                   "policy://vdec/conformance/root-ca",
		PolicyDecisionDigest:        crypto.SHA256Sum([]byte("vdec conformance policy decision")),
		RevocationCompletionDigest:  crypto.SHA256Sum([]byte("vdec conformance revocation completions")),
		TransparencyLogID:           "vdec-conformance-transparency",
		TransparencyInclusionProof:  [][]byte{proofNode},
		TransparencyTreeSize:        2,
		TransparencyCheckpointEpoch: finalEpoch,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	head, err := vdecverify.HeadForRecord(rec)
	if err != nil {
		t.Fatalf("HeadForRecord: %v", err)
	}
	published, err := record.Vector("vdec-destruction-record-v1", rec)
	if err != nil {
		t.Fatalf("Vector: %v", err)
	}
	req := vdecverify.Request{
		Record:          rec,
		VerificationKey: minter.PublicKey(),
		LogHead:         head,
		Retained:        vdecverify.RetainedEpoch{StableKeyID: stableKeyID, Epoch: finalEpoch},
		Completion:      &completion,
	}
	if verdict, err := vdecverify.Verify(req); err != nil || verdict.Determination != vdecverify.DeterminationDestroyedAfterReprotection {
		t.Fatalf("built vector does not verify: verdict=%+v err=%v", verdict, err)
	}
	return destructionRecordVector{
		Version:               1,
		Description:           "VDEC r1 destruction record vector: gated destroy after recorded re-protection, release, and erasure evidence",
		Vector:                published,
		Request:               req,
		ExpectedDetermination: vdecverify.DeterminationDestroyedAfterReprotection,
		Completion:            completion,
	}
}

func decodePublishedRecord(v destructionRecordVector) (record.SignedRecord, error) {
	rec, err := record.DecodeRecord(v.Vector.EncodedRecord)
	if err != nil {
		return record.SignedRecord{}, err
	}
	encoded, err := record.EncodeRecord(rec)
	if err != nil {
		return record.SignedRecord{}, err
	}
	if !bytes.Equal(encoded, v.Vector.EncodedRecord) {
		return record.SignedRecord{}, errors.New("canonical encode/decode round trip changed vector bytes")
	}
	reqEncoded, err := record.EncodeRecord(v.Request.Record)
	if err != nil {
		return record.SignedRecord{}, err
	}
	if !bytes.Equal(reqEncoded, v.Vector.EncodedRecord) {
		return record.SignedRecord{}, errors.New("request record does not match published encoded vector")
	}
	return rec, nil
}

func verifyVector(v destructionRecordVector) error {
	rec, err := decodePublishedRecord(v)
	if err != nil {
		return err
	}
	if err := record.VerifyRecord(rec, v.Request.VerificationKey); err != nil {
		return err
	}
	verdict, err := verifyRequest(v.Request)
	if err != nil {
		return err
	}
	if verdict.Determination != v.ExpectedDetermination {
		return fmt.Errorf("determination %q != %q", verdict.Determination, v.ExpectedDetermination)
	}
	return nil
}

func verifyRequest(req vdecverify.Request) (vdecverify.Verdict, error) {
	return vdecverify.Verify(req)
}

func wasmVerifyRequest(req vdecverify.Request) (vdecverify.Verdict, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return vdecverify.Verdict{}, err
	}
	out, err := vdecwasm.VerifyJSON(raw)
	if err != nil {
		return vdecverify.Verdict{}, err
	}
	var resp vdecwasm.Response
	if err := json.Unmarshal(out, &resp); err != nil {
		return vdecverify.Verdict{}, err
	}
	if !resp.OK {
		return vdecverify.Verdict{}, errors.New(resp.Error)
	}
	return resp.Verdict, nil
}

func differentialCommitmentDigest(rec record.SignedRecord) ([]byte, error) {
	c := rec.Commitment
	c.Transparency.LeafDigest = nil
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	wrapped, err := json.Marshal(struct {
		Domain     string `json:"domain"`
		Commitment []byte `json:"commitment"`
	}{Domain: rec.Commitment.Domain, Commitment: raw})
	if err != nil {
		return nil, err
	}
	return sha(wrapped), nil
}

func sha(b []byte) []byte {
	return crypto.SHA256Sum(b)
}

func same(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func vectorRecordSeed() []byte {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		return []byte("{}")
	}
	var v destructionRecordVector
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("{}")
	}
	return append([]byte(nil), v.Vector.EncodedRecord...)
}

func vectorRequestSeed() []byte {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		return []byte("{}")
	}
	var v destructionRecordVector
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte("{}")
	}
	out, err := json.Marshal(v.Request)
	if err != nil {
		return []byte("{}")
	}
	return out
}

func depstateEventSeed() []byte {
	ev, err := depstate.Encode(depstate.DependencyRegisteredV1{
		TenantID:  "tenant-a",
		KeyID:     "key://tenant-a/root-ca",
		Dependent: depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ct-1"},
		Origin:    depstate.RegistrationOriginIssued,
	})
	if err != nil {
		return []byte("{}")
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return []byte("{}")
	}
	return raw
}
