// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// P13-L1: work notes on the ServiceNow ticket an intake-opened request came
// from, queued for a network relay in the decision's projection transaction.

// TicketNoteDestination is the relay job kind that adds a work note.
const TicketNoteDestination = "ticket.note"

// IssuanceRequestTx reads one request inside a transaction.
func (s *Store) IssuanceRequestTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (IssuanceRequest, bool, error) {
	r, err := scanIssuanceRequest(tx.QueryRow(ctx, `SELECT `+issuanceRequestCols+` FROM issuance_requests
		WHERE tenant_id = $1 AND id::text = $2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return IssuanceRequest{}, false, nil
	}
	return r, err == nil, err
}

// ServiceNowIntakeScheduleForTableTx is the enabled ServiceNow intake schedule
// reading table, the first by name: a decision's work note goes back through it.
func (s *Store) ServiceNowIntakeScheduleForTableTx(ctx context.Context, tx pgx.Tx, tenantID, table string) (TicketIntakeSchedule, bool, error) {
	sched, err := scanTicketIntake(tx.QueryRow(ctx, `SELECT `+ticketIntakeCols+` FROM ticket_intake_schedules
		WHERE tenant_id = $1 AND system = 'servicenow' AND sn_table = $2 AND enabled ORDER BY name LIMIT 1`, tenantID, table))
	if errors.Is(err, pgx.ErrNoRows) {
		return TicketIntakeSchedule{}, false, nil
	}
	return sched, err == nil, err
}

// QueueTicketNoteTx queues one work note for a network relay unless the same
// note is queued already: a replayed decision queues nothing new, and the
// relay's read of the ticket keeps a re-run note from being added twice.
func (s *Store) QueueTicketNoteTx(ctx context.Context, tx pgx.Tx, tenantID, noteID string, payload []byte) error {
	key := "ticket-note:" + noteID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"outbox-enqueue-if-absent\x1f"+tenantID+"\x1f"+key); err != nil {
		return fmt.Errorf("store: lock the ticket note: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role)
		 SELECT $1, $2, $3, $4, $2, 'network'
		  WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $4)`,
		tenantID, TicketNoteDestination, payload, key); err != nil {
		return fmt.Errorf("store: queue the ticket note: %w", err)
	}
	return nil
}
