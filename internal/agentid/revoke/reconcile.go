// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Reconcile heals the narrow crash window between the durable-first directive append
// and the pg transaction that records the directive projection + enqueues the
// per-descendant outbox jobs (the G3 design). EnqueueDirective appends the
// RevocationDirective event first (durable, AN-2 source of truth), then commits the
// directive/job rows ⊕ the outbox jobs in one tx. If the process dies in that gap, the
// directive event survives but no jobs were enqueued — a directive recorded but never
// acted on.
//
// This pass makes the cascade log-derivable: it replays the ledger from `from`, and
// for each RevocationDirective event it re-derives the descendant set as of the
// event's recorded watermark and, in ONE pg transaction, inserts the directive/job
// rows (ON CONFLICT DO NOTHING) AND enqueues each per-descendant outbox job
// idempotently (EnqueueIfAbsent, keyed by the per-job idempotency key, itself derived
// from the durable-first directive event id). A directive whose jobs already landed
// (the common case) is left untouched; one lost to a crash is enqueued exactly once.
// It returns how many outbox jobs it healed. It is safe to run repeatedly and on boot.
//
// It does NOT re-append the directive event (that is the source of truth) and never
// flips terminal (AGID-11). Determination is reproducible because the descendant set
// is a pure fold of the ledger prefix up to the recorded watermark (§7.1 / INV-A8), so
// the healed jobs are exactly those the original transaction would have enqueued.
func (c *Cascade) Reconcile(ctx context.Context, from uint64) (int, error) {
	healed := 0
	if from == 0 {
		from = 1
	}
	err := c.log.Replay(ctx, from, func(ev eventspec.Event) error {
		if ev.Type != delegation.TypeRevocationDirective {
			return nil
		}
		pl, err := delegation.Decode(ev)
		if err != nil {
			return fmt.Errorf("revoke: reconcile decode directive (seq %d): %w", ev.Sequence, err)
		}
		dirPL, ok := pl.(delegation.RevocationDirectiveV1)
		if !ok {
			// A newer directive schema this build does not understand: skip (carry).
			return nil
		}
		reason := ReasonClass(dirPL.Reason)
		if !reason.Valid() {
			return fmt.Errorf("revoke: reconcile directive (seq %d): unrecognized reason %q", ev.Sequence, dirPL.Reason)
		}

		// The directive id the jobs are keyed under: the durable-first event id (the
		// original enqueue used the event id when no explicit id was supplied). A caller
		// that supplied an explicit id also recorded its own directive/job rows; this
		// pass keys by the event id, which is the id the inline enqueue used absent an
		// explicit id, so the reconciled jobs match. (Explicit-id directives are
		// reconciled by the same key derivation the caller used; see EnqueueDirective.)
		directiveID := ev.ID

		// Re-derive the descendant set as of the RECORDED watermark (reproducible fold).
		descendants, err := c.descendantsAsOf(ctx, ev.TenantID, dirPL.SubjectID, dirPL.Watermark)
		if err != nil {
			return err
		}

		dir := agidstore.RevocationDirective{
			DirectiveID: directiveID,
			SubjectID:   dirPL.SubjectID,
			Reason:      dirPL.Reason,
			Watermark:   dirPL.Watermark,
			Terminal:    false,
			Seq:         ev.Sequence,
		}
		jobRows := make([]agidstore.RevocationJob, 0, len(descendants))
		for _, cred := range descendants {
			jobRows = append(jobRows, agidstore.RevocationJob{
				DirectiveID:    directiveID,
				IdempotencyKey: JobIdempotencyKey(directiveID, cred),
				CredentialID:   cred,
				FollowOn:       false,
			})
		}

		return c.core.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
			// Directive + job rows, ON CONFLICT DO NOTHING (idempotent re-drive). The
			// directive INSERT is not conflict-guarded in the Tx helper, so a directive
			// row that already exists would raise; guard by inserting the directive row
			// with ON CONFLICT here, then the jobs via the Tx helper (which guards jobs).
			if _, err := tx.Exec(ctx,
				`INSERT INTO agent_revocation_directives
				   (tenant_id, directive_id, subject_id, reason, watermark, terminal, seq)
				 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, $5, $6)
				 ON CONFLICT (tenant_id, directive_id) DO NOTHING`,
				dir.DirectiveID, dir.SubjectID, dir.Reason, dir.Watermark, dir.Terminal, dir.Seq); err != nil {
				return fmt.Errorf("revoke: reconcile directive row: %w", err)
			}
			for _, j := range jobRows {
				if _, err := tx.Exec(ctx,
					`INSERT INTO agent_revocation_jobs
					   (tenant_id, directive_id, idempotency_key, credential_id, follow_on, completion_ref, seq)
					 VALUES (current_setting('trstctl.tenant_id')::uuid, $1, $2, $3, $4, NULL, 0)
					 ON CONFLICT (tenant_id, directive_id, idempotency_key) DO NOTHING`,
					directiveID, j.IdempotencyKey, j.CredentialID, j.FollowOn); err != nil {
					return fmt.Errorf("revoke: reconcile job row %q: %w", j.IdempotencyKey, err)
				}
			}
			for _, cred := range descendants {
				body, err := JobPayload{
					TenantID:          ev.TenantID,
					DirectiveID:       directiveID,
					CredentialID:      cred,
					Reason:            reason,
					PublishDownstream: true,
				}.encode()
				if err != nil {
					return err
				}
				inserted, err := c.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
					TenantID:       ev.TenantID,
					Destination:    DestinationRevocationJob,
					IdempotencyKey: JobIdempotencyKey(directiveID, cred),
					Payload:        body,
				})
				if err != nil {
					return err
				}
				if inserted {
					healed++
				}
			}
			return nil
		})
	})
	if err != nil {
		return healed, fmt.Errorf("revoke: reconcile: %w", err)
	}
	return healed, nil
}
