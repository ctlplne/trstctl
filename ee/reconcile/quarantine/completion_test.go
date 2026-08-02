// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	xrecplan "trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/ee/reconcile/quarantine"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCompletion_RegenAgreesOverSubset(t *testing.T) {
	ctx := context.Background()
	mgr, log, evidence := openQuarantine(t)
	req := completionRequest(t, evidence, "shared-post-remediation")

	decision, err := mgr.Complete(ctx, req)
	if err != nil {
		t.Fatalf("Complete agreed subset: %v", err)
	}
	if !decision.Completed || decision.CompletionID == "" || len(decision.Released) != 1 {
		t.Fatalf("decision = %+v, want one completed release", decision)
	}
	if rec, ok := mgr.State().Lookup("tenant-a", "vault"); !ok || rec.Open || rec.State != quarantine.StateConsistent {
		t.Fatalf("state after completion = %+v ok=%v, want closed consistent", rec, ok)
	}
	if countEvents(log.events, quarantine.EventTypeCompleted) != 1 || countEvents(log.events, quarantine.EventTypeReleased) != 1 {
		t.Fatalf("events = %+v, want completion and release", log.events)
	}

	stillDivergedMgr, _, stillDivergedEvidence := openQuarantine(t)
	stillDiverged := completionRequest(t, stillDivergedEvidence, "shared-post-remediation")
	different := completedDigest(t, "tenant-a", "kms", "wm-kms-3", "different-post-remediation")
	stillDiverged.CompletingDigests[1] = different.signed
	stillDiverged.Records[0].Proofs[1] = completionProof(t, different.signed, "different-post-remediation")
	if _, err := stillDivergedMgr.Complete(ctx, stillDiverged); !errors.Is(err, quarantine.ErrInvalidCompletion) {
		t.Fatalf("Complete disagreed subset error = %v, want ErrInvalidCompletion", err)
	}
	if rec, ok := stillDivergedMgr.State().Lookup("tenant-a", "vault"); !ok || !rec.Open || rec.State != quarantine.StateQuarantined {
		t.Fatalf("state after failed completion = %+v ok=%v, want still open quarantined", rec, ok)
	}
}

// The reconciliation-completion record binds witness and plan (XREC-claim-5).
func TestCompletion_RecordBindsWitnessAndPlan(t *testing.T) {
	mgr, log, evidence := openQuarantine(t)
	req := completionRequest(t, evidence, "shared-post-remediation")

	decision, err := mgr.Complete(context.Background(), req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var recorded quarantine.Completed
	decodeEvent(t, findEvent(t, log.events, quarantine.EventTypeCompleted), &recorded)
	if recorded.WitnessID != evidence.Body.WitnessID || recorded.PlanID != req.Plan.Plan.PlanID ||
		recorded.WitnessHash != hex.EncodeToString(evidence.ContentHash()) ||
		recorded.PlanHash != hex.EncodeToString(req.Plan.PlanHash) ||
		recorded.CompletionID != decision.CompletionID {
		t.Fatalf("completion record = %+v, does not bind witness and plan", recorded)
	}
	if err := quarantine.VerifyCompletionChain(evidence, req.Plan, recorded); err != nil {
		t.Fatalf("VerifyCompletionChain: %v", err)
	}
	tampered := recorded
	tampered.PlanHash = "00" + recorded.PlanHash
	if err := quarantine.VerifyCompletionChain(evidence, req.Plan, tampered); !errors.Is(err, quarantine.ErrInvalidCompletion) {
		t.Fatalf("VerifyCompletionChain tampered error = %v, want ErrInvalidCompletion", err)
	}
}

// Release happens only through a completion record (XREC-claim-5).
func TestQuarantine_ReleasedOnlyByCompletion(t *testing.T) {
	ctx := context.Background()
	mgr, _, evidence := openQuarantine(t)

	unsigned := quarantine.OperatorOverride{
		TenantID:          "tenant-a",
		AuthorityID:       "vault",
		WitnessID:         evidence.Body.WitnessID,
		JustificationRef:  "INC-123",
		OperatorID:        "ops-1",
		KeyID:             "ops-key",
		SignedAt:          fixedNow().Unix(),
		ReleaseReasonText: "manual evidence review",
	}
	if _, err := mgr.OverrideRelease(ctx, "idem-unsigned", unsigned); !errors.Is(err, quarantine.ErrInvalidOverride) {
		t.Fatalf("OverrideRelease unsigned error = %v, want ErrInvalidOverride", err)
	}
	if rec, ok := mgr.State().Lookup("tenant-a", "vault"); !ok || !rec.Open {
		t.Fatalf("state after unsigned override = %+v ok=%v, want still open", rec, ok)
	}

	if _, err := mgr.Complete(ctx, completionRequest(t, evidence, "shared-post-remediation")); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	allowed, err := mgr.Admit(ctx, editionseam.AdmissionRequest{
		TenantID:       "tenant-a",
		Operation:      "issue",
		IdentityID:     "identity-after-completion",
		IdempotencyKey: "idem-admit-after-completion",
		ObservedInputs: []editionseam.ObservedStateInput{{AuthorityID: "vault", Source: "policy"}},
	})
	if err != nil {
		t.Fatalf("Admit after completion: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("Admit after completion = %+v, want allowed", allowed)
	}

	overrideMgr, _, overrideEvidence := openQuarantine(t)
	override, err := signedOverride("tenant-a", "vault", overrideEvidence.Body.WitnessID)
	if err != nil {
		t.Fatalf("signedOverride: %v", err)
	}
	if _, err := overrideMgr.OverrideRelease(ctx, "idem-signed-override", override); err != nil {
		t.Fatalf("OverrideRelease signed: %v", err)
	}
	if rec, ok := overrideMgr.State().Lookup("tenant-a", "vault"); !ok || rec.Open || rec.State != quarantine.StateConsistent {
		t.Fatalf("state after signed override = %+v ok=%v, want closed consistent", rec, ok)
	}
}

func TestCompletion_OutboxHandlerDrivesRelease(t *testing.T) {
	mgr, _, evidence := openQuarantine(t)
	req := completionRequest(t, evidence, "shared-post-remediation")
	payload, err := quarantine.EncodeCompletionJob(req)
	if err != nil {
		t.Fatalf("EncodeCompletionJob: %v", err)
	}
	handler := quarantine.NewHandler(mgr)
	handled, err := handler.DeliverLicensed(context.Background(), orchestrator.Message{
		TenantID:       "tenant-a",
		Destination:    quarantine.DestinationCompletion,
		IdempotencyKey: req.IdempotencyKey,
		Payload:        payload,
	})
	if err != nil {
		t.Fatalf("DeliverLicensed: %v", err)
	}
	if !handled {
		t.Fatal("completion handler did not handle completion destination")
	}
	if rec, ok := mgr.State().Lookup("tenant-a", "vault"); !ok || rec.Open {
		t.Fatalf("state after outbox completion = %+v ok=%v, want released", rec, ok)
	}
}

func openQuarantine(t *testing.T) (*quarantine.Manager, *memoryLog, witness.Evidence) {
	t.Helper()
	log := &memoryLog{}
	mgr := quarantine.NewManager(quarantine.Options{
		Log:          log,
		Idempotency:  idem.NewMemory(),
		Policy:       quarantine.ReferencePolicy("vault"),
		Now:          fixedNow,
		OverrideKeys: trustedOverrideKeys(t),
	})
	evidence := policyViolationEvidence("tenant-a", "vault")
	if _, err := mgr.ObserveWitness(context.Background(), "idem-enter-"+evidence.Body.WitnessID, evidence); err != nil {
		t.Fatalf("ObserveWitness: %v", err)
	}
	return mgr, log, evidence
}

func completionRequest(t *testing.T, evidence witness.Evidence, value string) quarantine.CompletionRequest {
	t.Helper()
	vault := completedDigest(t, "tenant-a", "vault", "wm-vault-2", value)
	kms := completedDigest(t, "tenant-a", "kms", "wm-kms-2", value)
	key := evidence.Body.Entries[0].Policy.RecordKey
	witnessHash := evidence.ContentHash()
	return quarantine.CompletionRequest{
		IdempotencyKey:    "completion-" + evidence.Body.WitnessID,
		Witness:           evidence,
		Plan:              signedPlanForCompletion(t, evidence.Body.WitnessID, witnessHash, key),
		CompletingRoundID: "round-2",
		CompletingDigests: []digest.SignedDigest{vault.signed, kms.signed},
		Records: []quarantine.CompletedRecordProof{{
			RecordKey: key,
			Proofs: []quarantine.CompletedProof{
				completionProof(t, vault.signed, value),
				completionProof(t, kms.signed, value),
			},
		}},
	}
}

func signedPlanForCompletion(t *testing.T, witnessID string, witnessHash []byte, key canon.RecordKey) xrecplan.SignedPlan {
	t.Helper()
	plan := xrecplan.Plan{
		PlanID:      "plan-10",
		TenantID:    key.TenantID,
		WitnessID:   witnessID,
		WitnessHash: append([]byte(nil), witnessHash...),
		Actions: []xrecplan.Action{{
			AuthorityID: "vault",
			RecordKey:   key,
			Operation:   "rotate-key",
		}},
		GeneratedAt: fixedNow().Unix(),
	}
	hash, err := plan.Hash()
	if err != nil {
		t.Fatalf("plan hash: %v", err)
	}
	return xrecplan.SignedPlan{Plan: plan, PlanHash: hash, AuthorityID: "xrec-plan", KeyID: "plan-key", PublicKeyDER: []byte{1}, Signature: []byte{2}, SignedAt: fixedNow().Unix()}
}

type completedDigestFixture struct {
	signed digest.SignedDigest
	tree   *digest.Tree
}

func completedDigest(t *testing.T, tenantID, authorityID, position, value string) completedDigestFixture {
	t.Helper()
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, []canon.ObservedRecord{{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeX509Certificate,
		StableID:   "cert-a",
		Algorithm:  "RSA_2048",
		Status:     canon.StatusActive,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: "cert-a"},
		Attributes: map[string]canon.Value{"reconciled_value": canon.String(value)},
	}})
	if err != nil {
		t.Fatalf("ReduceTenant: %v", err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Watermark:   digest.Watermark{Position: position, ObservedAt: fixedNow().Unix()},
		GeneratedAt: fixedNow().Unix(),
	})
	if err != nil {
		t.Fatalf("digest.Build: %v", err)
	}
	hash, err := built.Body.DigestHash()
	if err != nil {
		t.Fatalf("DigestHash: %v", err)
	}
	return completedDigestFixture{
		signed: digest.SignedDigest{Body: built.Body, DigestHash: hash, KeyID: authorityID + "-digest-key", PublicKeyDER: []byte{1}, Signature: []byte{2}},
		tree:   built.Tree,
	}
}

func completionProof(t *testing.T, signed digest.SignedDigest, value string) quarantine.CompletedProof {
	t.Helper()
	fixture := completedDigest(t, signed.Body.TenantID, signed.Body.AuthorityID, signed.Body.Watermark.Position, value)
	keyBytes, err := digest.RecordKeyBytes(canon.RecordKey{TenantID: signed.Body.TenantID, RecordType: canon.RecordTypeX509Certificate, StableID: "cert-a"})
	if err != nil {
		t.Fatalf("RecordKeyBytes: %v", err)
	}
	proof, ok := fixture.tree.InclusionProof(keyBytes)
	if !ok {
		t.Fatal("missing inclusion proof")
	}
	if !bytes.Equal(fixture.signed.DigestHash, signed.DigestHash) {
		t.Fatalf("fixture digest hash mismatch for %s", signed.Body.AuthorityID)
	}
	return quarantine.CompletedProof{
		AuthorityID: signed.Body.AuthorityID,
		Proof: witness.InclusionProof{
			RecordKeyBytes:       proof.RecordKeyBytes,
			CanonicalRecordBytes: proof.CanonicalRecordBytes,
			Siblings:             convertProofNodes(proof.Siblings),
		},
	}
}

func convertProofNodes(in []digest.ProofNode) []witness.ProofNode {
	out := make([]witness.ProofNode, len(in))
	for i, n := range in {
		out[i] = witness.ProofNode{Hash: append([]byte(nil), n.Hash...), Left: n.Left}
	}
	return out
}

var overrideSigner crypto.Signer

func trustedOverrideKeys(t *testing.T) map[string]crypto.PublicKey {
	t.Helper()
	if overrideSigner == nil {
		signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		overrideSigner = signer
	}
	return map[string]crypto.PublicKey{"ops-key": overrideSigner.Public()}
}

func signedOverride(tenantID, authorityID, witnessID string) (quarantine.OperatorOverride, error) {
	o := quarantine.OperatorOverride{
		TenantID:          tenantID,
		AuthorityID:       authorityID,
		WitnessID:         witnessID,
		JustificationRef:  "INC-456",
		OperatorID:        "ops-1",
		KeyID:             "ops-key",
		Algorithm:         overrideSigner.Algorithm(),
		PublicKeyDER:      overrideSigner.Public().DER,
		SignedAt:          fixedNow().Unix(),
		ReleaseReasonText: "manual evidence review",
	}
	payload, err := o.CanonicalBytes()
	if err != nil {
		return quarantine.OperatorOverride{}, err
	}
	sig, err := overrideSigner.Sign(payload, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return quarantine.OperatorOverride{}, err
	}
	o.Signature = sig
	return o, nil
}

func findEvent(t *testing.T, events []eventspec.Event, typ string) eventspec.Event {
	t.Helper()
	for _, ev := range events {
		if ev.Type == typ {
			return ev
		}
	}
	t.Fatalf("event %s not found in %+v", typ, events)
	return eventspec.Event{}
}
