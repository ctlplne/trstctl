// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestCR126UnrelatedKeyCannotForgeRevocationEvidence(t *testing.T) {
	issuer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	key := issuer.Public().DER // Pinned outside either artifact.
	completion := CompletionEvidence{
		TenantID: "tenant", DirectiveID: "directive", IdempotencyKey: "job",
		CredentialID: "credential", EffectClass: EffectRevoke,
		CompletedAt: 1_700_000_000, Executor: "worker",
	}
	genuineJob, _, err := signCompletionEvidence(issuer, completion)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompletionEvidence(genuineJob, key); err != nil {
		t.Fatalf("genuine completion evidence: %v", err)
	}
	completion.CredentialID = "never-revoked"
	forgedJob, _, err := signCompletionEvidence(attacker, completion)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCompletionEvidence(forgedJob, key); err == nil {
		t.Error("completion evidence signed by an unrelated key was accepted")
	}

	digest := crypto.SHA256Sum([]byte("job evidence"))
	aggregate := AggregateEvidence{
		TenantID: "tenant", DirectiveID: "directive", SubjectID: "subject",
		ReasonClass: ReasonRootPrincipalRequest, Watermark: 1, LedgerHead: 1,
		JobCount: 1, CompletionEvidenceDigest: CompletionEvidenceDigestOf([][]byte{digest}),
	}
	genuineAggregate, err := signAggregate(issuer, aggregate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAggregateOffline(genuineAggregate, [][]byte{digest}, key); err != nil {
		t.Fatalf("genuine aggregate: %v", err)
	}
	aggregate.SubjectID = "never-revoked"
	forgedAggregate, err := signAggregate(attacker, aggregate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAggregateOffline(forgedAggregate, [][]byte{digest}, key); err == nil {
		t.Error("aggregate signed by an unrelated key was accepted")
	}
}
