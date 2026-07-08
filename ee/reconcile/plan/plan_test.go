// SPDX-License-Identifier: LicenseRef-trstctl-EE

package plan_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/plan"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func TestPlan_BindsWitnessHash(t *testing.T) {
	fixture := mustPlanFixture(t)
	decision, err := fixture.Gate.VerifyOperation(context.Background(), fixture.Request(t, fixture.SignedPlan, fixture.Envelope))
	if err != nil {
		t.Fatalf("VerifyOperation valid plan: %v", err)
	}
	if !decision.Approved || len(decision.Authorization) == 0 {
		t.Fatalf("decision = %+v, want approved authorization", decision)
	}

	badPlan := fixture.Plan
	badPlan.WitnessHash = []byte("not-the-recorded-witness-hash")
	badSigned := fixture.SignPlan(t, badPlan)
	decision, err = fixture.Gate.VerifyOperation(context.Background(), fixture.Request(t, badSigned, fixture.Envelope))
	if err != nil {
		t.Fatalf("VerifyOperation mismatched hash: %v", err)
	}
	fixture.AssertRefusal(t, decision, plan.CheckWitnessHash)

	unrecordedRaw, err := json.Marshal(plan.VerificationEnvelope{})
	if err != nil {
		t.Fatalf("marshal unrecorded envelope: %v", err)
	}
	decision, err = fixture.Gate.VerifyOperation(context.Background(), signing.OperationRequest{
		TenantID:       fixture.Plan.TenantID,
		Operation:      "delete",
		SubjectRef:     plan.RecordKeyRef(fixture.RecordKey),
		Preconditions:  fixture.MustEncodePlan(t, fixture.SignedPlan),
		Evidence:       unrecordedRaw,
		IdempotencyKey: "idem-unrecorded",
	})
	if err != nil {
		t.Fatalf("VerifyOperation unrecorded witness: %v", err)
	}
	fixture.AssertRefusal(t, decision, plan.CheckWitnessRecorded)
}

func TestPlan_VerifyFailureEmitsSignedRefusal(t *testing.T) {
	fixture := mustPlanFixture(t)
	untrustedGate, err := plan.NewOperationGate(plan.GateConfig{
		ArtifactSigner: fixture.ArtifactSigner,
		SignerID:       "trstctl-signer",
		Clock:          fixedClock,
	})
	if err != nil {
		t.Fatalf("NewOperationGate: %v", err)
	}
	decision, err := untrustedGate.VerifyOperation(context.Background(), fixture.Request(t, fixture.SignedPlan, fixture.Envelope))
	if err != nil {
		t.Fatalf("VerifyOperation untrusted plan: %v", err)
	}
	refusal := fixture.AssertRefusal(t, decision, plan.CheckPlanSignature)
	if refusal.Body.PlanID != fixture.Plan.PlanID || refusal.Body.WitnessHash != hex.EncodeToString(fixture.Plan.WitnessHash) {
		t.Fatalf("refusal linkage = %+v, want plan and witness hash", refusal.Body)
	}

	closed := fixture.Envelope
	closed.Closed = true
	decision, err = fixture.Gate.VerifyOperation(context.Background(), fixture.Request(t, fixture.SignedPlan, closed))
	if err != nil {
		t.Fatalf("VerifyOperation closed witness: %v", err)
	}
	fixture.AssertRefusal(t, decision, plan.CheckWitnessClosed)

	needsCounter := fixture.Envelope
	needsCounter.RequiredCountersignFrom = "kms"
	decision, err = fixture.Gate.VerifyOperation(context.Background(), fixture.Request(t, fixture.SignedPlan, needsCounter))
	if err != nil {
		t.Fatalf("VerifyOperation missing countersign: %v", err)
	}
	fixture.AssertRefusal(t, decision, plan.CheckCountersign)
}

type planFixture struct {
	ArtifactSigner *digest.ArtifactSigner
	PlanKey        *crypto.LockedSigner
	Gate           *plan.OperationGate
	RecordKey      canon.RecordKey
	Plan           plan.Plan
	SignedPlan     plan.SignedPlan
	Envelope       plan.VerificationEnvelope
}

func mustPlanFixture(t *testing.T) planFixture {
	t.Helper()
	artifactSigner, err := digest.NewArtifactSigner(digest.ArtifactSignerConfig{SignerID: "xrec-test-signer"})
	if err != nil {
		t.Fatalf("NewArtifactSigner: %v", err)
	}
	t.Cleanup(artifactSigner.Destroy)
	planKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(planKey.Destroy)

	recordKey := canon.RecordKey{TenantID: "tenant-a", RecordType: canon.RecordTypeKey, StableID: "vault/key-a"}
	body := witness.Body{
		RoundID:     "round-1",
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		DigestRefs: []witness.DigestRef{
			{
				AuthorityID:  "vault",
				DigestHash:   []byte("vault-digest"),
				KeyID:        "digest-vault",
				Algorithm:    crypto.ECDSAP256,
				PublicKeyDER: []byte("digest-public-vault"),
				Signature:    []byte("digest-signature-vault"),
				Watermark:    digest.Watermark{Position: "vault-42", ObservedAt: 1799999900},
			},
			{
				AuthorityID:  "kms",
				DigestHash:   []byte("kms-digest"),
				KeyID:        "digest-kms",
				Algorithm:    crypto.ECDSAP256,
				PublicKeyDER: []byte("digest-public-kms"),
				Signature:    []byte("digest-signature-kms"),
				Watermark:    digest.Watermark{Position: "kms-42", ObservedAt: 1799999900},
			},
		},
		Entries: []witness.Entry{{
			RecordKey:        recordKey,
			Class:            witness.ClassPresence,
			PresentAuthority: "vault",
		}},
		GeneratedAt: 1800000000,
	}
	body.WitnessID = hex.EncodeToString(body.WitnessHash())
	signedWitness, err := witness.Sign(context.Background(), artifactSigner, body, "")
	if err != nil {
		t.Fatalf("Sign witness: %v", err)
	}
	evidence, err := witness.EvidenceFromSignedWitness(signedWitness)
	if err != nil {
		t.Fatalf("EvidenceFromSignedWitness: %v", err)
	}
	recorded := witness.WitnessRecorded{
		WitnessID:   evidence.Body.WitnessID,
		TenantID:    evidence.Body.TenantID,
		RoundID:     evidence.Body.RoundID,
		WitnessHash: hex.EncodeToString(evidence.ContentHash()),
		Authorities: []string{"vault", "kms"},
		Evidence:    evidence,
	}
	p := plan.Plan{
		PlanID:      "plan-1",
		TenantID:    "tenant-a",
		WitnessID:   evidence.Body.WitnessID,
		WitnessHash: evidence.ContentHash(),
		Actions: []plan.Action{{
			AuthorityID: "vault",
			RecordKey:   recordKey,
			Operation:   "delete",
			Parameters:  map[string]string{"native_id": "vault/key-a"},
		}},
		GeneratedAt: 1800000100,
	}
	signedPlan, err := plan.Sign(context.Background(), planKey, p, "operator-plan-authority", "plan-key-1", 1800000101)
	if err != nil {
		t.Fatalf("Sign plan: %v", err)
	}
	gate, err := plan.NewOperationGate(plan.GateConfig{
		TrustedPlanKeys: map[string]crypto.PublicKey{
			signedPlan.KeyID: planKey.Public(),
		},
		TrustedWitnessKeys: map[string]crypto.PublicKey{
			artifactSigner.WitnessKeyID(): artifactSigner.WitnessPublic(),
		},
		ArtifactSigner: artifactSigner,
		SignerID:       "trstctl-signer",
		Clock:          fixedClock,
	})
	if err != nil {
		t.Fatalf("NewOperationGate: %v", err)
	}
	return planFixture{
		ArtifactSigner: artifactSigner,
		PlanKey:        planKey,
		Gate:           gate,
		RecordKey:      recordKey,
		Plan:           p,
		SignedPlan:     signedPlan,
		Envelope:       plan.VerificationEnvelope{Recorded: recorded},
	}
}

func (f planFixture) SignPlan(t *testing.T, p plan.Plan) plan.SignedPlan {
	t.Helper()
	signed, err := plan.Sign(context.Background(), f.PlanKey, p, "operator-plan-authority", "plan-key-1", 1800000101)
	if err != nil {
		t.Fatalf("SignPlan: %v", err)
	}
	return signed
}

func (f planFixture) Request(t *testing.T, signed plan.SignedPlan, env plan.VerificationEnvelope) signing.OperationRequest {
	t.Helper()
	envRaw, err := plan.EncodeVerificationEnvelope(env)
	if err != nil {
		t.Fatalf("EncodeVerificationEnvelope: %v", err)
	}
	return signing.OperationRequest{
		TenantID:       f.Plan.TenantID,
		Operation:      "delete",
		SubjectRef:     plan.RecordKeyRef(f.RecordKey),
		IdempotencyKey: "idem-plan-1",
		Preconditions:  f.MustEncodePlan(t, signed),
		Evidence:       envRaw,
	}
}

func (f planFixture) MustEncodePlan(t *testing.T, signed plan.SignedPlan) []byte {
	t.Helper()
	raw, err := plan.EncodeSignedPlan(signed)
	if err != nil {
		t.Fatalf("EncodeSignedPlan: %v", err)
	}
	return raw
}

func (f planFixture) AssertRefusal(t *testing.T, decision signing.OperationDecision, failedCheck string) plan.RefusalRecord {
	t.Helper()
	if decision.Approved {
		t.Fatalf("decision = %+v, want refusal", decision)
	}
	refusal, err := plan.DecodeRefusalRecord(decision.RefusalRecord)
	if err != nil {
		t.Fatalf("DecodeRefusalRecord: %v", err)
	}
	if refusal.Body.FailedCheck != failedCheck {
		t.Fatalf("failed_check = %q, want %q (body %+v)", refusal.Body.FailedCheck, failedCheck, refusal.Body)
	}
	if err := refusal.Verify(map[string]crypto.PublicKey{
		f.ArtifactSigner.RefusalKeyID(): f.ArtifactSigner.RefusalPublic(),
	}); err != nil {
		t.Fatalf("refusal Verify: %v", err)
	}
	return refusal
}

func fixedClock() time.Time {
	return time.Unix(1800000200, 0).UTC()
}
