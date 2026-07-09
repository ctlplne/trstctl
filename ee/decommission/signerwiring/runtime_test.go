// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/ee/decommission/aggregate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/internal/crypto"
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
