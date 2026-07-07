// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api

import (
	"context"

	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
)

// service_revocation.go serves the AGID-11 aggregate revocation-evidence read model. It
// imports ee/agentid/revoke ONLY for its pure read helpers (LoadTerminalArtifact, a log
// replay) — the revoke package links no reach engine and no broker, so this does not pull
// the mint path into the API request graph. The DEEP mechanisms (the cascade, the executor,
// the terminal transition itself) get their production callers in the orchestrator worker;
// this read surfaces the already-recorded, signed artifact for a relying party to verify
// offline with revoke.VerifyAggregateOffline.

// RevocationEvidence returns a directive's terminal verdict and its signed aggregate
// evidence artifact (AGID-11), RLS-scoped to tenantID. Terminal is the directive's
// recorded terminal flag; the Artifact (when present) is the encoded AggregateEvidence the
// terminal transition minted, loaded from the AN-2 ledger. A directive still draining has
// Terminal=false and no artifact, and its outstanding jobs are surfaced by IncompleteJobs.
func (s *service) RevocationEvidence(ctx context.Context, tenantID, directiveID string) (RevocationEvidenceResponse, error) {
	resp := RevocationEvidenceResponse{DirectiveID: directiveID}
	if s.repo == nil {
		return resp, nil
	}
	dir, found, err := s.repo.FetchRevocationDirective(ctx, tenantID, directiveID)
	if err != nil {
		return RevocationEvidenceResponse{}, err
	}
	if !found {
		return resp, nil
	}
	resp.Terminal = dir.Terminal

	// The obligation-set size is the number of jobs enqueued under the directive; the
	// still-open subset is IncompleteJobs. JobCount here is the total obligation set so an
	// operator sees progress (JobCount - len(Missing) completed).
	jobs, err := s.repo.FetchRevocationJobs(ctx, tenantID, directiveID)
	if err != nil {
		return RevocationEvidenceResponse{}, err
	}
	resp.JobCount = len(jobs)
	for _, j := range jobs {
		eff, found, err := s.repo.FetchEffect(ctx, tenantID, directiveID, j.IdempotencyKey)
		if err != nil {
			return RevocationEvidenceResponse{}, err
		}
		if found && len(eff.EvidenceBody) != 0 {
			resp.EvidenceDigests = append(resp.EvidenceDigests, crypto.SHA256Sum(eff.EvidenceBody))
		}
	}
	incomplete, err := s.repo.IncompleteJobs(ctx, tenantID, directiveID)
	if err != nil {
		return RevocationEvidenceResponse{}, err
	}
	for _, j := range incomplete {
		resp.Missing = append(resp.Missing, j.IdempotencyKey)
	}

	// Load the signed aggregate evidence artifact from the ledger when the directive has
	// reached terminal (a pure log read; no signer needed on the read path). Absent means
	// the cascade has not evidenced completion yet.
	if s.log != nil {
		artifact, ok, err := revoke.LoadTerminalArtifact(ctx, s.log, tenantID, directiveID)
		if err != nil {
			return RevocationEvidenceResponse{}, err
		}
		if ok {
			resp.Artifact = artifact
		}
	}
	return resp, nil
}
