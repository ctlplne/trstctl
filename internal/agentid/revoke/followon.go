// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/orchestrator"
)

// FollowOnResult reports the follow-on jobs a GenerateFollowOn pass created: the
// descendant credentials that were discovered AFTER the directive's watermark and now
// carry a follow-on job under the same directive (§7.2, AGID-claim-16).
type FollowOnResult struct {
	DirectiveID string
	NewJobs     []string // descendant credential ids that got a follow-on job
}

// GenerateFollowOn chases late-arriving descendants (§7.2). A sub-delegation minted
// moments before the directive but whose IssuanceRecorded/DelegationRecorded events
// were sequenced AFTER the directive's determining watermark is invisible to the
// original determination; at replay it is discovered. This pass recomputes the
// descendant set for the subject AS OF the CURRENT ledger head, diffs it against the
// jobs already enqueued under the directive, and — for each newly-discovered
// descendant — enqueues a FOLLOW-ON job under the SAME directive: a job row (follow_on
// = true) + one outbox job, committed in ONE pg transaction (INV-A8). It is
// idempotent: a descendant that already has a job (original or follow-on) is skipped
// via EnqueueIfAbsent + ON CONFLICT, so running the pass repeatedly adds each
// late descendant exactly once. It performs no key operation and never flips terminal
// (AGID-11).
func (c *Cascade) GenerateFollowOn(ctx context.Context, tenantID, directiveID string) (FollowOnResult, error) {
	if tenantID == "" || directiveID == "" {
		return FollowOnResult{}, fmt.Errorf("revoke: GenerateFollowOn requires tenant and directive id")
	}

	// The directive we are chasing late descendants for (its subject + reason).
	dir, found, err := c.repo.FetchRevocationDirective(ctx, tenantID, directiveID)
	if err != nil {
		return FollowOnResult{}, err
	}
	if !found {
		return FollowOnResult{}, fmt.Errorf("revoke: directive %q not found for follow-on", directiveID)
	}

	// Recompute the descendant set as of the CURRENT ledger head (which is >= the
	// directive watermark), so descendants recorded after the watermark are now folded.
	head, err := c.ledgerHead(ctx)
	if err != nil {
		return FollowOnResult{}, err
	}
	currentSet, err := c.descendantsAsOf(ctx, tenantID, dir.SubjectID, head)
	if err != nil {
		return FollowOnResult{}, err
	}

	// The descendants already covered by a job (original or a prior follow-on).
	existingJobs, err := c.repo.FetchRevocationJobs(ctx, tenantID, directiveID)
	if err != nil {
		return FollowOnResult{}, err
	}
	covered := make(map[string]struct{}, len(existingJobs))
	for _, j := range existingJobs {
		covered[j.CredentialID] = struct{}{}
	}

	// The reason class is carried on the directive as a string; map it back for the
	// follow-on job payloads (an unrecognized stored reason is a corruption — fail).
	reason := ReasonClass(dir.Reason)
	if !reason.Valid() {
		return FollowOnResult{}, fmt.Errorf("revoke: directive %q has unrecognized stored reason %q", directiveID, dir.Reason)
	}

	var newCreds []string
	for _, cred := range currentSet {
		if _, ok := covered[cred]; ok {
			continue
		}
		newCreds = append(newCreds, cred)
	}
	if len(newCreds) == 0 {
		return FollowOnResult{DirectiveID: directiveID}, nil
	}

	// ONE pg tx: follow-on job rows + follow-on outbox jobs (INV-A8), same shape as
	// the original enqueue but follow_on = true.
	err = c.core.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		followJobs := make([]agidstore.RevocationJob, 0, len(newCreds))
		for _, cred := range newCreds {
			followJobs = append(followJobs, agidstore.RevocationJob{
				DirectiveID:    directiveID,
				IdempotencyKey: JobIdempotencyKey(directiveID, cred),
				CredentialID:   cred,
				FollowOn:       true,
			})
		}
		// Directive row already exists; re-inserting it would collide. Insert only the
		// follow-on job rows (ON CONFLICT DO NOTHING guards a concurrent pass), so we
		// call the per-job insert path with an already-present directive by reusing the
		// Tx helper but with the existing directive values (its INSERT collides
		// harmlessly under ON CONFLICT for jobs; the directive INSERT would raise, so we
		// insert jobs directly here instead).
		for _, j := range followJobs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO agent_revocation_jobs
				   (tenant_id, directive_id, idempotency_key, credential_id, follow_on, completion_ref, seq)
				 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, NULL, 0)
				 ON CONFLICT (tenant_id, directive_id, idempotency_key) DO NOTHING`,
				directiveID, j.IdempotencyKey, j.CredentialID, j.FollowOn); err != nil {
				return fmt.Errorf("revoke: insert follow-on job %q: %w", j.IdempotencyKey, err)
			}
		}
		for _, cred := range newCreds {
			body, err := JobPayload{
				TenantID:          tenantID,
				DirectiveID:       directiveID,
				CredentialID:      cred,
				Reason:            reason,
				FollowOn:          true,
				PublishDownstream: true,
			}.encode()
			if err != nil {
				return err
			}
			if _, err := c.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    DestinationRevocationJob,
				IdempotencyKey: JobIdempotencyKey(directiveID, cred),
				Payload:        body,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return FollowOnResult{}, fmt.Errorf("revoke: commit follow-on jobs: %w", err)
	}

	return FollowOnResult{DirectiveID: directiveID, NewJobs: newCreds}, nil
}
