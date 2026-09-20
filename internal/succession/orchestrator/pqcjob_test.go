// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/succession/minter"
	"trstctl.com/trstctl/internal/succession/orchestrator"
)

// TestMintRequestForJob_CarriesTargetAndPolicyRef: the glue maps a planned PQC
// succession job to a signer MintRequest carrying the job's target algorithm and
// reproducible policy_ref (PCAS-claim-23), plus the operational binding. No PG needed.
func TestMintRequestForJob_CarriesTargetAndPolicyRef(t *testing.T) {
	job := pqcmigration.SuccessionJob{
		IdentityID:      "spiffe://d/id",
		CredentialType:  pqcmigration.CredentialX509,
		TargetAlgorithm: pqcmigration.TargetMLDSA65,
		PolicyRef:       "sha256:abc123",
	}
	req := orchestrator.MintRequestForJob(job, orchestrator.JobBinding{
		TenantID: tenantA, DeploymentScope: "spiffe://d", PredecessorHandle: "pred",
		AssertedPredecessorEpoch: 3, NotBefore: 1, NotAfter: 2,
	})
	if req.IdentityID != "spiffe://d/id" || req.TenantID != tenantA || req.DeploymentScope != "spiffe://d" {
		t.Fatalf("identity/tenant/scope not carried: %+v", req)
	}
	if string(req.TargetAlgorithm) != pqcmigration.TargetMLDSA65 {
		t.Fatalf("target = %q, want %q", req.TargetAlgorithm, pqcmigration.TargetMLDSA65)
	}
	if req.PolicyRef != "sha256:abc123" {
		t.Fatalf("policy_ref = %q, want sha256:abc123", req.PolicyRef)
	}
	if req.PredecessorHandle != "pred" || req.AssertedPredecessorEpoch != 3 {
		t.Fatalf("binding not carried: %+v", req)
	}
}

// TestRunJob_MintsAndRecords: a planned job (here with a classical target so the
// software backend can generate the successor key) runs end-to-end through the
// orchestrator — the minted record binds the job's policy_ref and target — proving
// the PCAS-09 → PCAS-08 wiring.
func TestRunJob_MintsAndRecords(t *testing.T) {
	orch, cm, _ := setup(t)
	ctx := context.Background()

	job := pqcmigration.SuccessionJob{
		IdentityID:      "spiffe://d/job",
		CredentialType:  pqcmigration.CredentialX509,
		TargetAlgorithm: string(crypto.ECDSAP384), // classical: keygen-able by the software backend
		PolicyRef:       "sha256:job-policy-ref",
	}
	res, err := orch.RunJob(ctx, job, orchestrator.JobBinding{
		TenantID: tenantA, DeploymentScope: "spiffe://d", PredecessorHandle: "pred",
		AssertedPredecessorEpoch: 0, NotBefore: 1, NotAfter: 1000,
	}, "job-key-1")
	if err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if res.Epoch != 1 || cm.calls != 1 {
		t.Fatalf("epoch=%d calls=%d, want 1,1", res.Epoch, cm.calls)
	}
	rec, err := minter.DecodeRecord(res.Record)
	if err != nil {
		t.Fatalf("decode minted record: %v", err)
	}
	if rec.Fields.PolicyRef != "sha256:job-policy-ref" {
		t.Fatalf("minted record policy_ref = %q, want the job's", rec.Fields.PolicyRef)
	}
	if rec.Fields.SuccessorAlg != crypto.ECDSAP384 {
		t.Fatalf("minted successor alg = %q, want ECDSA-P384", rec.Fields.SuccessorAlg)
	}
	// Idempotent replay under the same key mints no second time.
	res2, err := orch.RunJob(ctx, job, orchestrator.JobBinding{
		TenantID: tenantA, DeploymentScope: "spiffe://d", PredecessorHandle: "pred",
		AssertedPredecessorEpoch: 0, NotBefore: 1, NotAfter: 1000,
	}, "job-key-1")
	if err != nil {
		t.Fatalf("RunJob replay: %v", err)
	}
	if !res2.Replayed || cm.calls != 1 {
		t.Fatalf("replay=%v calls=%d, want true,1", res2.Replayed, cm.calls)
	}
}
