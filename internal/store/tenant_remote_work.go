// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RequireTenantAgentWorkQuiescent checks durable agent claims and control-plane
// receiver attempts after the caller excludes new work with the service barrier.
// Remote work can continue after its RPC, lease or process session has ended.
func (s *Store) RequireTenantAgentWorkQuiescent(ctx context.Context, tenantID string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.RequireTenantAgentWorkQuiescentTx(ctx, tx, tenantID)
	})
}

// RequireTenantAgentWorkQuiescentTx refuses until every issued attempt has a
// verified terminal receipt. Expiry/reclamation and a later attempt's success
// do not prove that an earlier executor stopped. The outbox retention sweep
// preserves rows with missing receipts so this check cannot age into a pass.
func (s *Store) RequireTenantAgentWorkQuiescentTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var id int64
	var destination string
	var pending int
	err := tx.QueryRow(ctx, `SELECT id, destination, cardinality(receiver_pending_ids) FROM outbox
		WHERE tenant_id=$1 AND cardinality(receiver_pending_ids)>0 ORDER BY id LIMIT 1`, tenantID).Scan(&id, &destination, &pending)
	if err != nil && err != pgx.ErrNoRows {
		return fmt.Errorf("store: inspect unresolved control-plane deliveries: %w", err)
	}
	if err == nil {
		return fmt.Errorf("%w: outbox %d (%s) has %d control-plane delivery attempts without terminal receiver evidence", ErrTenantServiceBusy, id, destination, pending)
	}
	var unresolved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM outbox AS queued WHERE queued.tenant_id=$1
		AND (queued.claim_attempts < 0
		 OR (queued.claim_attempts=0 AND queued.claimed_by_agent_id IS NOT NULL)
		 OR queued.claim_attempts <> (
			SELECT count(*) FROM agent_job_receipts AS receipt
			WHERE receipt.tenant_id=queued.tenant_id AND receipt.job_id=queued.id
			 AND receipt.attempt BETWEEN 1 AND queued.claim_attempts
			 AND receipt.state='verified'
			 AND receipt.outcome IN ('executed','verified','verify_failed','failed')
			 AND receipt.statement<>'' AND receipt.signature<>''
			 AND receipt.signer_fingerprint<>''
		 )))`, tenantID).Scan(&unresolved); err != nil {
		return fmt.Errorf("store: inspect unresolved remote agent work: %w", err)
	}
	if unresolved {
		return fmt.Errorf("%w: remote agent attempts still lack verified terminal receipts", ErrTenantServiceBusy)
	}
	return nil
}
