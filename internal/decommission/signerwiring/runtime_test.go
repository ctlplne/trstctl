// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/aggregate"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/decommission/retirement"
	"trstctl.com/trstctl/internal/signing"
)

func TestRuntimeSignsVDECArtifactsInsideSigner(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(Config{SignerID: "test-vdec-signer", FloorDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	mint := validRecordRequest(t)
	recordPayload, err := json.Marshal(mint)
	if err != nil {
		t.Fatalf("marshal record request: %v", err)
	}
	recordSig, err := runtime.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        ArtifactKindDestructionRecord,
		TenantID:    mint.TenantID,
		AuthorityID: "vdec-record-minter",
		Payload:     recordPayload,
	})
	if err != nil {
		t.Fatalf("SignArtifact destruction record: %v", err)
	}
	if recordSig.KeyID != defaultDestructionRecordKeyID || len(recordSig.PublicKeyDER) == 0 || len(recordSig.Signature) == 0 {
		t.Fatalf("destruction record signature = %+v, want public signer material", recordSig)
	}

	perKey, err := runtime.RecordMinter.Mint(ctx, mint)
	if err != nil {
		t.Fatalf("Mint per-key record for countersignature: %v", err)
	}

	countersignPayload, err := json.Marshal(perKey)
	if err != nil {
		t.Fatalf("marshal countersignature request: %v", err)
	}
	countersig, err := runtime.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        ArtifactKindRecordCountersignature,
		TenantID:    mint.TenantID,
		AuthorityID: "distinct-vdec-authority",
		Payload:     countersignPayload,
	})
	if err != nil {
		t.Fatalf("SignArtifact countersignature: %v", err)
	}
	if countersig.KeyID != defaultCountersignatureKeyID || len(countersig.PublicKeyDER) == 0 || len(countersig.Signature) == 0 {
		t.Fatalf("countersignature = %+v, want public signer material", countersig)
	}

	aggregatePayload, err := json.Marshal(aggregate.MintRequest{
		TenantID:                mint.TenantID,
		Records:                 []aggregate.LeafInput{{KeyClass: "root-ca", Record: perKey}},
		AuditChainHead:          "audit-head-after-campaign",
		InventoryLedgerPosition: 88,
		InventoryKeyIDs:         []string{mint.StableKeyID},
	})
	if err != nil {
		t.Fatalf("marshal aggregate record request: %v", err)
	}
	aggregateSig, err := runtime.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:     ArtifactKindAggregateRecord,
		TenantID: mint.TenantID,
		Payload:  aggregatePayload,
	})
	if err != nil {
		t.Fatalf("SignArtifact aggregate record: %v", err)
	}
	if aggregateSig.KeyID != defaultAggregateRecordKeyID || len(aggregateSig.PublicKeyDER) == 0 || len(aggregateSig.Signature) == 0 {
		t.Fatalf("aggregate signature = %+v, want public signer material", aggregateSig)
	}
}

func TestRuntimeFinalizesFullOfflineRecordAfterGatedDestroy(t *testing.T) {
	runtime, err := NewRuntime(Config{SignerID: "test-vdec-signer", FloorDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	defer runtime.Destroy()
	completionDigest := crypto.SHA256Sum([]byte("completion-digest"))
	revocationDigest := crypto.SHA256Sum([]byte("revocation-digest"))
	requested := retirement.RequestedV1{
		TenantID: "tenant-a", KeyID: "key://tenant-a/root-ca", SignerHandle: "handle-a",
		FinalEpoch: 42, LedgerPosition: 9, RequiredSet: []byte("required"),
		RequiredSetDigest: crypto.SHA256Sum([]byte("required")), AuditChainHead: []byte("audit-head"),
		CompletionEventsDigest:     completionDigest,
		RevocationCompletionDigest: revocationDigest, KeyClass: "ca-signing-key",
	}
	finalization, err := retirement.EncodeFinalizationContext("command-event-a", requested)
	if err != nil {
		t.Fatalf("EncodeFinalizationContext: %v", err)
	}
	quorum, err := gate.EncodeQuorumEvidence(gate.QuorumEvidence{
		KeyClass: requested.KeyClass, Threshold: 2, AuthorizedCount: 3,
		Approvers: []string{"alice@example.test", "bob@example.test"},
	})
	if err != nil {
		t.Fatalf("EncodeQuorumEvidence: %v", err)
	}
	decision, err := runtime.FinalizeGatedDestroy(context.Background(), signing.GatedDestroyRequest{
		TenantID: requested.TenantID, Handle: requested.SignerHandle, SubjectRef: requested.KeyID,
		AssertedFinalEpoch: requested.FinalEpoch, RequiredSetDigest: requested.RequiredSetDigest,
		AuditChainHead: requested.AuditChainHead, Context: finalization,
	}, signing.GatedDestroyDecision{Approved: true, Authorization: quorum})
	if err != nil {
		t.Fatalf("FinalizeGatedDestroy: %v", err)
	}
	rec, err := record.DecodeRecord(decision.Evidence)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if rec.Commitment.StableKeyID != requested.KeyID || rec.Commitment.FinalEpoch != requested.FinalEpoch ||
		!bytes.Equal(rec.Commitment.CompletionEventsDigest, completionDigest) ||
		!bytes.Equal(rec.Commitment.RevocationCompletionDigest, revocationDigest) {
		t.Fatalf("record commitment = %+v", rec.Commitment)
	}
	if evidence := rec.Commitment.QuorumEvidence; evidence == nil || !evidence.ApproversRedacted ||
		len(evidence.Approvers) != 0 || evidence.ApprovalCount != 2 || len(evidence.ApproverDigest) != 32 {
		t.Fatalf("public record quorum evidence = %+v, want identity-free threshold proof", evidence)
	}
	rawRecord, err := record.EncodeRecord(rec)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	if bytes.Contains(rawRecord, []byte("alice")) || bytes.Contains(rawRecord, []byte("bob")) {
		t.Fatalf("public destruction record retained operator identities: %s", rawRecord)
	}
	if err := record.VerifyRecord(rec, crypto.PublicKey{
		Algorithm: rec.AttestationAlgorithm, DER: rec.AttestationPublicKeyDER,
	}); err != nil {
		t.Fatalf("offline VerifyRecord: %v", err)
	}
}

func TestRuntimeDestroyZeroizesSignerHeldKeys(t *testing.T) {
	runtime, err := NewRuntime(Config{SignerID: "test-vdec-signer", FloorDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	runtime.Destroy()
	if runtime.Gate != nil || runtime.RecordMinter != nil || runtime.AggregateMinter != nil ||
		runtime.ControlPlaneOutageCeremony != nil || runtime.Countersigner != nil {
		t.Fatalf("Destroy left signer-held components reachable: %+v", runtime)
	}
}

func validRecordRequest(t *testing.T) record.MintRequest {
	t.Helper()
	return record.MintRequest{
		TenantID:               "tenant-a",
		StableKeyID:            "key://tenant-a/root-ca",
		FinalEpoch:             42,
		CompletionEventsDigest: []byte("completion-events-digest"),
		RequiredSetDigest:      []byte("required-set-digest"),
		DestructionEvidence: record.EvidenceFromDestruction(gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           "tenant-a",
			StableKeyID:        "key://tenant-a/root-ca",
			FinalEpoch:         42,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("hsm destroy attestation statement"),
			Digest:             []byte("destruction-evidence-digest"),
		}),
		AuditChainHead:             "audit-head-after-destruction",
		Successors:                 []record.SuccessorKey{successor(t, "succ-a", 43)},
		PolicyRef:                  "policy://destruction/root-ca",
		PolicyDecisionDigest:       []byte("policy-decision-digest"),
		RevocationCompletionDigest: []byte("revocation-completion-digest"),
		TransparencyLogID:          "vdec-transparency-log",
		TransparencyRootDigest:     []byte("transparency-root"),
		TransparencyInclusionProof: [][]byte{[]byte("proof-node-a"), []byte("proof-node-b")},
		TransparencyTreeSize:       9,
	}
}

func successor(t *testing.T, id string, epoch uint64) record.SuccessorKey {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey successor: %v", err)
	}
	defer k.Destroy()
	pub := k.Public()
	return record.SuccessorKey{ID: id, Epoch: epoch, Algorithm: pub.Algorithm, PublicDER: pub.DER}
}
