// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/signing"
)

// pqcjob.go is the glue from PQC migration planning (PCAS-09) to the succession
// orchestrator: a pqcmigration.SuccessionJob carries the policy-decided target and
// a reproducible policy_ref, and this maps it onto the generic signer MintRequest
// so the job drives a recorded, outbox-published succession (PCAS-08).

// JobBinding carries the operational parameters not known at PQC planning time —
// tenant, deployment scope, the in-signer predecessor handle, the asserted
// predecessor epoch, the validity window, and any signer-verified authorization
// artifacts — bound when a planned job becomes a MintRequest.
type JobBinding struct {
	TenantID                 string
	DeploymentScope          string
	PredecessorHandle        string
	AssertedPredecessorEpoch uint64
	NotBefore                int64
	NotAfter                 int64
	PolicyDecision           []byte // signer-verified policy artifact (PCAS-claim-23)
	Authorization            []byte // dual-control authorization token (PCAS-claim-5)
	BreakGlass               []byte // strength-downgrade break-glass token (PCAS-claim-17)
}

// MintRequestForJob maps a PQC-planned succession job to the generic signer
// MintRequest, carrying the job's target algorithm and reproducible policy_ref
// (PCAS-claim-23) alongside the operational binding. The predecessor key is referenced
// only by handle; no key material crosses into the request.
func MintRequestForJob(job pqcmigration.SuccessionJob, b JobBinding) signing.MintRequest {
	return signing.MintRequest{
		IdentityID:               job.IdentityID,
		TenantID:                 b.TenantID,
		DeploymentScope:          b.DeploymentScope,
		PredecessorHandle:        b.PredecessorHandle,
		AssertedPredecessorEpoch: b.AssertedPredecessorEpoch,
		TargetAlgorithm:          crypto.Algorithm(job.TargetAlgorithm),
		PolicyRef:                job.PolicyRef,
		PolicyDecision:           b.PolicyDecision,
		Authorization:            b.Authorization,
		BreakGlass:               b.BreakGlass,
		NotBefore:                b.NotBefore,
		NotAfter:                 b.NotAfter,
	}
}

// RunJob binds a planned succession job to operational parameters and runs it as an
// idempotent succession (mint → record + outbox in one transaction) under
// idempotencyKey. It is the end-to-end entry that turns PQC planning output into a
// recorded succession.
func (o *Orchestrator) RunJob(ctx context.Context, job pqcmigration.SuccessionJob, b JobBinding, idempotencyKey string) (Result, error) {
	return o.RunSuccession(ctx, b.TenantID, MintRequestForJob(job, b), idempotencyKey)
}
