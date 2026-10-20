// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// SecretSyncReceiverEffectSettled marks a delivered command that needed more
	// than one receiver start and whose receiver state was then read back (or
	// attested by an operator) as exactly this command's value. It releases the
	// per-target FIFO barrier that a multi-start delivery otherwise keeps.
	SecretSyncReceiverEffectSettled SecretSyncReceiverEffectState = "effect_settled"
	// SecretSyncReceiverFailureReconciled marks a command whose receiver state
	// was read back (or attested) as never holding this command's value, so its
	// failure releases successors whatever its start count.
	SecretSyncReceiverFailureReconciled SecretSyncReceiverEffectState = "failure_reconciled"
)

// SecretSyncReceiverSettledEventID is the deterministic identity of the one
// retained settlement receipt for a job; replaying it changes nothing.
func SecretSyncReceiverSettledEventID(tenantID, jobID string) string {
	return "secret-sync-settled-" + uuid.NewSHA1(secretSyncEventNamespace, []byte(tenantID+"\x00"+jobID)).String()
}

// secretSyncOlderCommandReleased is the one definition of "this older command
// no longer blocks its target lane". The outbox claim query carries the same
// text; keep them identical.
const secretSyncOlderCommandReleased = `(
    (older_job.status = 'delivered'
        AND ((older_outbox.secret_sync_receiver_effect_state = 'effect_possible'
                AND older_outbox.secret_sync_receiver_io_starts = 1)
             OR older_outbox.secret_sync_receiver_effect_state = 'effect_settled'))
    OR
    (older_job.status = 'failed'
        AND ((older_outbox.secret_sync_receiver_effect_state = 'failure_authorized'
                AND older_outbox.secret_sync_receiver_io_starts BETWEEN 0 AND 1)
             OR older_outbox.secret_sync_receiver_effect_state = 'failure_reconciled')
        AND older_outbox.secret_sync_failure_detail = older_job.last_error
        AND older_outbox.secret_sync_failure_attempts = older_job.attempts)
)`

// ApplySecretSyncReceiverSettledTx is called only by the projector for a
// secret.sync.receiver_settled event. The job must already be delivered: the
// settlement receipt is appended after the delivered receipt and replays in
// that order. A job erased by tenant offboarding reports pgx.ErrNoRows so the
// caller can treat the late receipt as inert; an outbox row already purged by
// retention needs nothing, the retained event is the evidence.
func (s *Store) ApplySecretSyncReceiverSettledTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, jobID string, outboxID int64) error {
	if tenantID == "" || tenantEpoch == "" || jobID == "" || outboxID <= 0 {
		return errors.New("store: secret-sync settlement is incomplete")
	}
	tag, err := tx.Exec(ctx, `
		UPDATE outbox AS queued
		   SET secret_sync_receiver_effect_state = 'effect_settled'
		  FROM secret_sync_jobs AS job
		 WHERE job.tenant_id = $1 AND job.tenant_epoch = $2 AND job.id = $3 AND job.outbox_id = $4
		   AND job.status = 'delivered'
		   AND queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
		   AND queued.destination = 'secret.sync.' || job.target
		   AND queued.secret_sync_target_order = job.target_order
		   AND queued.secret_sync_receiver_effect_state IN ('effect_possible', 'effect_settled')`,
		tenantID, tenantEpoch, jobID, outboxID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM secret_sync_jobs WHERE tenant_id = $1 AND tenant_epoch = $2 AND id = $3`,
		tenantID, tenantEpoch, jobID).Scan(&status)
	if err != nil {
		return err
	}
	if status != string(SecretSyncJobDelivered) {
		return fmt.Errorf("%w: secret-sync settlement for job %s precedes its delivered outcome", ErrIdempotencyConflict, jobID)
	}
	return nil
}

// AuthorizeSecretSyncReconciledNoEffect converts effect_possible to the
// reconciled failure authority after an independent receiver readback (or an
// explicit operator attestation) proved the receiver never took this command's
// value. Unlike the only-started form it accepts any start count: the proof is
// the readback, not the absence of requests. The caller holds the
// terminal-choice lock; false means the job already left the pending state.
func (s *Store) AuthorizeSecretSyncReconciledNoEffect(
	ctx context.Context,
	tenantID, jobID string,
	outboxID int64,
	failureDetail string,
	failureAttempts int,
) (authorized bool, err error) {
	if tenantID == "" || jobID == "" || outboxID <= 0 || failureDetail == "" || failureAttempts < 1 {
		return false, errors.New("store: authorize secret-sync reconciled failure is incomplete")
	}
	err = s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx, `
			UPDATE outbox AS queued
			   SET secret_sync_receiver_effect_state = 'failure_reconciled',
			       secret_sync_failure_detail = $4,
			       secret_sync_failure_attempts = $5
			  FROM secret_sync_jobs AS job
			 WHERE job.tenant_id = $1 AND job.id = $2 AND job.outbox_id = $3
			   AND job.status = 'pending' AND job.target_order > 0
			   AND queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order
			   AND queued.status IN ('pending', 'processing')
			   AND queued.secret_sync_receiver_effect_state = 'effect_possible'`,
			tenantID, jobID, outboxID, failureDetail, failureAttempts)
		if execErr != nil {
			return execErr
		}
		if tag.RowsAffected() == 1 {
			authorized = true
			return nil
		}
		var authority SecretSyncReceiverAuthority
		if err := loadSecretSyncReceiverAuthorityTx(ctx, tx, tenantID, jobID, outboxID, &authority); err != nil {
			return err
		}
		switch {
		case authority.JobStatus != SecretSyncJobPending:
			return nil
		case authority.EffectState == SecretSyncReceiverFailureReconciled:
			if authority.FailureDetail != failureDetail || authority.FailureAttempts != failureAttempts {
				return fmt.Errorf("%w: secret-sync reconciled failure authority detail differs", ErrIdempotencyConflict)
			}
			authorized = true
			return nil
		default:
			return nil
		}
	})
	return authorized, err
}

// SecretSyncOutboxPayload returns the sealed command bytes of one job's own
// outbox row under RLS. The caller opens them inside the tenant key domain and
// wipes them; nothing here decrypts.
func (s *Store) SecretSyncOutboxPayload(ctx context.Context, tenantID string, outboxID int64, target string) ([]byte, error) {
	if tenantID == "" || outboxID <= 0 || target == "" {
		return nil, errors.New("store: secret-sync outbox payload lookup is incomplete")
	}
	var payload []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND id = $2 AND destination = $3`,
			tenantID, outboxID, "secret.sync."+target).Scan(&payload)
	})
	return payload, err
}

// SecretSyncBlockingPredecessor names the oldest older command on the same
// tenant+target lane that still holds the FIFO barrier in front of jobID. It is
// read-only and tenant scoped; an empty result means the job is not blocked by
// a predecessor.
func (s *Store) SecretSyncBlockingPredecessor(ctx context.Context, tenantID, jobID string) (string, bool, error) {
	if tenantID == "" || jobID == "" {
		return "", false, errors.New("store: secret-sync predecessor lookup is incomplete")
	}
	var predecessor string
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(older_job.id, '')
			  FROM secret_sync_jobs current_job
			  JOIN outbox current_outbox
			    ON current_outbox.tenant_id = current_job.tenant_id
			   AND current_outbox.id = current_job.outbox_id
			  JOIN outbox older_outbox
			    ON older_outbox.tenant_id = current_outbox.tenant_id
			   AND older_outbox.destination = current_outbox.destination
			   AND older_outbox.secret_sync_target_order < current_outbox.secret_sync_target_order
			  LEFT JOIN secret_sync_jobs older_job
			    ON older_job.tenant_id = older_outbox.tenant_id
			   AND older_job.outbox_id = older_outbox.id
			   AND older_job.target_order = older_outbox.secret_sync_target_order
			   AND older_outbox.destination = 'secret.sync.' || older_job.target
			 WHERE current_job.tenant_id = $1 AND current_job.id = $2
			   AND current_outbox.secret_sync_target_order > 0
			   AND NOT COALESCE(`+secretSyncOlderCommandReleased+`, false)
			 ORDER BY older_outbox.secret_sync_target_order
			 LIMIT 1`, tenantID, jobID).Scan(&predecessor)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return predecessor, found, err
}
