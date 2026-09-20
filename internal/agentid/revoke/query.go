// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"

	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
)

// query.go exposes the incomplete-jobs projection query (AGID-claim-22): "did the kill
// finish?" as a ledger query. It returns the set of revocation jobs under a directive for
// which signed completion evidence has NOT been recorded — the jobs that stand between the
// directive and its terminal revoked-with-evidence state. It is a pure read over the
// AGID-02 projection (control plane); it performs no key op and no mutation.

// IncompleteJob names one job of a cascade whose signed completion evidence has not been
// recorded yet: the credential it targets, its idempotency key, and whether it is a
// follow-on. It is the projection's answer to "which jobs of this kill have not finished?"
type IncompleteJob struct {
	DirectiveID    string
	IdempotencyKey string
	CredentialID   string
	FollowOn       bool
}

// IncompleteJobs returns the jobs enqueued under directiveID that have no recorded signed
// completion evidence (AGID-claim-22), scoped to tenantID by RLS, ordered deterministically by
// idempotency key. An empty slice means every enqueued and follow-on job is evidenced —
// the cascade is complete and the directive is eligible for the terminal transition
// (terminal.go). It reads the AGID-02 projection (jobs LEFT of the effect ledger), so a
// caller can poll it to see the kill converge without replaying the whole event log.
//
// This is the OPERATOR-facing complement to the terminal gate: the terminal transition
// asserts completeness as a signed fact; this query surfaces the OUTSTANDING obligations
// while the cascade is still draining, naming exactly the jobs whose evidence is missing
// (which, under an incomplete cascade, is exactly the not-yet-executed descendants).
func IncompleteJobs(ctx context.Context, repo *agidstore.Repo, tenantID, directiveID string) ([]IncompleteJob, error) {
	rows, err := repo.IncompleteJobs(ctx, tenantID, directiveID)
	if err != nil {
		return nil, err
	}
	out := make([]IncompleteJob, 0, len(rows))
	for _, j := range rows {
		out = append(out, IncompleteJob{
			DirectiveID:    j.DirectiveID,
			IdempotencyKey: j.IdempotencyKey,
			CredentialID:   j.CredentialID,
			FollowOn:       j.FollowOn,
		})
	}
	return out, nil
}
