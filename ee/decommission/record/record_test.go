// SPDX-License-Identifier: LicenseRef-trstctl-EE

package record

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func TestRecord_CommitmentBindsClaim1Fields(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	req := validRequest(t)

	rec, err := minter.Mint(ctx, req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := VerifyRecord(rec, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
	c := rec.Commitment
	if c.StableKeyID != req.StableKeyID || c.FinalEpoch != req.FinalEpoch ||
		!bytes.Equal(c.CompletionEventsDigest, req.CompletionEventsDigest) ||
		!bytes.Equal(c.DestructionEvidence.Digest, req.DestructionEvidence.Digest) ||
		c.AuditChainHead != req.AuditChainHead {
		t.Fatalf("commitment = %+v, want VDEC-claim-1 fields bound", c)
	}

	tampered := rec
	tampered.Commitment.CompletionEventsDigest = []byte("different-completion-digest")
	if err := VerifyRecord(tampered, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered completion digest error = %v, want unverified", err)
	}

	tampered = rec
	tampered.Commitment.DestructionEvidence.Digest = []byte("different-destroy-evidence")
	if err := VerifyRecord(tampered, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered destruction evidence error = %v, want unverified", err)
	}
}

func TestRecord_MintedInsideSignerWithAttestationKey(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	rec, err := minter.Mint(ctx, validRequest(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	pub := minter.PublicKey()
	if rec.SignerID != "test-vdec-signer" || rec.AttestationAlgorithm != pub.Algorithm || !bytes.Equal(rec.AttestationPublicKeyDER, pub.DER) {
		t.Fatalf("record attestation key = signer %q alg %q len(pub) %d, want signer-held key metadata", rec.SignerID, rec.AttestationAlgorithm, len(rec.AttestationPublicKeyDER))
	}
	if len(rec.Signature) == 0 || len(rec.CommitmentDigest) == 0 {
		t.Fatal("minted record has empty signature or commitment digest")
	}
	if err := VerifyRecord(rec, pub); err != nil {
		t.Fatalf("VerifyRecord with signer-held attestation key: %v", err)
	}
}

func TestRecord_ControlPlaneHoldsNoAttestationKey(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	rec, err := minter.Mint(ctx, validRequest(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	controlPlaneKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey attacker: %v", err)
	}
	defer controlPlaneKey.Destroy()
	forgedSig, err := controlPlaneKey.SignDigest(rec.CommitmentDigest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("control-plane forge signature: %v", err)
	}
	forged := rec
	forged.Signature = forgedSig
	if err := VerifyRecord(forged, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord forged signature error = %v, want unverified", err)
	}

	forged = rec
	forged.AttestationPublicKeyDER = controlPlaneKey.Public().DER
	forged.AttestationAlgorithm = controlPlaneKey.Public().Algorithm
	forged.Signature = forgedSig
	if err := VerifyRecord(forged, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord forged key metadata error = %v, want unverified", err)
	}
}

func TestRecord_BindsSuccessorAndAuditHead(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	req := validRequest(t)
	req.AuditChainHead = ""
	req.AuditSeed = "checkpoint-head-before-destroy"
	req.AuditRecords = destructionAuditRecords()
	req.Successors = []SuccessorKey{
		successor(t, "succ-b", 8),
		successor(t, "succ-a", 7),
	}

	rec, err := minter.Mint(ctx, req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := VerifyRecord(rec, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
	if got, want := rec.Commitment.AuditChainHead, SealAuditHead(req.AuditSeed, req.AuditRecords); got != want {
		t.Fatalf("audit head = %q, want sealed-through-destroy head %q", got, want)
	}
	if len(rec.Commitment.Successors) != 2 || rec.Commitment.Successors[0].ID != "succ-a" || rec.Commitment.Successors[1].ID != "succ-b" {
		t.Fatalf("successors = %+v, want deterministic ordered binding of both successors", rec.Commitment.Successors)
	}

	tamperedRecords := destructionAuditRecords()
	tamperedRecords[1].Data = json.RawMessage(`{"destroy":"tampered"}`)
	if got, original := SealAuditHead(req.AuditSeed, tamperedRecords), rec.Commitment.AuditChainHead; got == original {
		t.Fatal("tampered destruction event did not change recomputed audit head")
	}

	tampered := rec
	tampered.Commitment.Successors[1].PublicDER = []byte("different-successor-public-key")
	if err := VerifyRecord(tampered, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered successor error = %v, want unverified", err)
	}

	tampered = rec
	tampered.Commitment.AuditChainHead = "different-audit-chain-head"
	if err := VerifyRecord(tampered, minter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered audit head error = %v, want unverified", err)
	}
}

func TestRecord_CanonicalEncodingStable(t *testing.T) {
	ctx := context.Background()
	minter := newTestMinter(t)
	rec, err := minter.Mint(ctx, validRequest(t))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	first, err := EncodeRecord(rec)
	if err != nil {
		t.Fatalf("EncodeRecord first: %v", err)
	}
	decoded, err := DecodeRecord(first)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	second, err := EncodeRecord(decoded)
	if err != nil {
		t.Fatalf("EncodeRecord second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical encoding changed after round trip\nfirst:  %s\nsecond: %s", first, second)
	}
	if _, err := VerifyEncoded(second, minter.PublicKey()); err != nil {
		t.Fatalf("VerifyEncoded: %v", err)
	}
	vector, err := Vector("vdec-destruction-record-v1", decoded)
	if err != nil {
		t.Fatalf("Vector: %v", err)
	}
	if vector.Domain == "" || len(vector.EncodedRecord) == 0 || len(vector.EncodedRecordDigest) == 0 || len(vector.AttestationPublicKeyDER) == 0 {
		t.Fatalf("vector = %+v, want published verifier vector material", vector)
	}
}

func newTestMinter(t *testing.T) *Minter {
	t.Helper()
	minter, err := NewMinter(Config{
		SignerID:  "test-vdec-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000400, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)
	return minter
}

func validRequest(t *testing.T) MintRequest {
	t.Helper()
	return MintRequest{
		TenantID:               "tenant-a",
		StableKeyID:            "key://tenant-a/root-ca",
		FinalEpoch:             42,
		CompletionEventsDigest: []byte("completion-events-digest"),
		RequiredSetDigest:      []byte("required-set-digest"),
		DestructionEvidence: EvidenceFromDestruction(gate.DestructionEvidence{
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
		Successors:                 []SuccessorKey{successor(t, "succ-a", 43)},
		PolicyRef:                  "policy://destruction/root-ca",
		PolicyDecisionDigest:       []byte("policy-decision-digest"),
		RevocationCompletionDigest: []byte("revocation-completion-digest"),
		TransparencyLogID:          "vdec-transparency-log",
		TransparencyRootDigest:     []byte("transparency-root"),
		TransparencyInclusionProof: [][]byte{[]byte("proof-node-a"), []byte("proof-node-b")},
		TransparencyTreeSize:       9,
	}
}

func successor(t *testing.T, id string, epoch uint64) SuccessorKey {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey successor: %v", err)
	}
	defer k.Destroy()
	pub := k.Public()
	return SuccessorKey{ID: id, Epoch: epoch, Algorithm: pub.Algorithm, PublicDER: pub.DER}
}

func destructionAuditRecords() []audit.Record {
	ts := time.Unix(1800000390, 0)
	return []audit.Record{
		{
			Sequence: 1,
			ID:       "completion",
			Type:     "vdec.completion",
			TenantID: "tenant-a",
			Time:     ts,
			Actor:    &events.Actor{Subject: "worker", Roles: []string{"vdec"}},
			Data:     json.RawMessage(`{"completion":"ok"}`),
		},
		{
			Sequence: 2,
			ID:       "destroy",
			Type:     gate.TypeCustodyHSMDestroyed,
			TenantID: "tenant-a",
			Time:     ts.Add(time.Second),
			Actor:    &events.Actor{Subject: "trstctl-signer", Roles: []string{"signer"}},
			Data:     json.RawMessage(`{"destroy":"ok"}`),
		},
	}
}
