// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ticketintake"
)

// TicketIntakeSweepPage is one already-validated provider page. The request
// events are projected separately; these counts and the cursor are the durable
// coverage checkpoint that says which provider rows have been considered.
type TicketIntakeSweepPage struct {
	System        string
	SweepID       string
	Cursor        string
	ReadBefore    int
	PageLimit     int
	ObservedAt    time.Time
	ReadCount     int
	ExpectedCount *int
	Complete      bool
	NextCursor    string
	Eligible      int
	Skipped       int
}

// ApplyTicketIntakeSweepDispatchedTx starts one exact named sweep. A different
// sweep cannot replace an incomplete cursor; that would silently abandon rows.
func (s *Store) ApplyTicketIntakeSweepDispatchedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	intent ticketintake.SyncIntent,
	at time.Time,
) error {
	var currentID, cursor string
	var complete bool
	err := tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, ''), cursor, coverage_complete
		   FROM ticket_intake_schedules
		  WHERE tenant_id = $1 AND system = $2 FOR UPDATE`, tenantID, intent.System).
		Scan(&currentID, &cursor, &complete)
	if err != nil {
		return err
	}
	if currentID == intent.SweepID && !complete {
		if cursor == "" {
			return nil
		}
		return fmt.Errorf("store: ticket intake sweep was already dispatched past its first page")
	}
	if currentID != "" && !complete {
		return fmt.Errorf("store: ticket intake schedule has an incomplete sweep")
	}
	_, err = tx.Exec(ctx,
		`UPDATE ticket_intake_schedules
		    SET current_sweep_id = $3, sweep_started_at = $4, last_attempt_at = $4,
		        cursor = '', read_count = 0, expected_count = NULL, pages_completed = 0,
		        coverage_complete = false, eligible_count = 0, skipped_count = 0,
		        last_error = '', updated_at = now()
		  WHERE tenant_id = $1 AND system = $2`, tenantID, intent.System, intent.SweepID, at.UTC())
	return err
}

// ApplyTicketIntakeSweepPageTx advances exactly the committed input cursor.
// Duplicate or older immutable events are no-ops; a future/out-of-order page
// fails closed so a replay cannot skip tickets.
func (s *Store) ApplyTicketIntakeSweepPageTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	page TicketIntakeSweepPage,
) error {
	var currentID, cursor string
	var readCount int
	var complete bool
	err := tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, ''), cursor, read_count, coverage_complete
		   FROM ticket_intake_schedules
		  WHERE tenant_id = $1 AND system = $2 FOR UPDATE`, tenantID, page.System).
		Scan(&currentID, &cursor, &readCount, &complete)
	if err != nil {
		return err
	}
	if currentID != page.SweepID {
		return fmt.Errorf("store: ticket intake page names a different sweep")
	}
	if readCount > page.ReadBefore || (readCount == page.ReadCount && (page.ReadCount > page.ReadBefore || complete)) {
		return nil
	}
	if complete || cursor != page.Cursor || readCount != page.ReadBefore {
		return fmt.Errorf("store: ticket intake page does not match the current cursor")
	}
	pageSize := page.ReadCount - page.ReadBefore
	if pageSize < 0 || pageSize > page.PageLimit || page.Eligible < 0 || page.Skipped < 0 ||
		page.Eligible+page.Skipped != pageSize || page.ObservedAt.IsZero() ||
		(page.ExpectedCount != nil && *page.ExpectedCount < page.ReadCount) ||
		(page.Complete && page.ExpectedCount != nil && *page.ExpectedCount != page.ReadCount) ||
		(page.Complete && page.NextCursor != "") || (!page.Complete && page.NextCursor == "") {
		return fmt.Errorf("store: invalid ticket intake page progress")
	}
	lastRun := any(nil)
	if page.Complete {
		lastRun = page.ObservedAt.UTC()
	}
	_, err = tx.Exec(ctx,
		`UPDATE ticket_intake_schedules
		    SET cursor = $3, read_count = $4, expected_count = $5,
		        pages_completed = pages_completed + 1, coverage_complete = $6,
		        eligible_count = eligible_count + $7, skipped_count = skipped_count + $8,
		        last_attempt_at = $9, last_run_at = coalesce($10, last_run_at),
		        last_error = '', updated_at = now()
		  WHERE tenant_id = $1 AND system = $2`,
		tenantID, page.System, page.NextCursor, page.ReadCount, page.ExpectedCount, page.Complete,
		page.Eligible, page.Skipped, page.ObservedAt.UTC(), lastRun)
	return err
}

// ApplyTicketIntakeSweepFailedTx records a failed attempt without changing the
// cursor or declaring coverage complete.
func (s *Store) ApplyTicketIntakeSweepFailedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, system, sweepID, cursor string,
	at time.Time,
	detail string,
) error {
	command, err := tx.Exec(ctx,
		`UPDATE ticket_intake_schedules
		    SET last_attempt_at = $5, last_error = $6, updated_at = now()
		  WHERE tenant_id = $1 AND system = $2 AND current_sweep_id = $3
		    AND cursor = $4 AND NOT coverage_complete`,
		tenantID, system, sweepID, cursor, at.UTC(), detail)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return fmt.Errorf("store: ticket intake failure does not match the current cursor")
	}
	return nil
}

// ValidateTicketIntakeIntentTx binds scheduler recovery to the exact projected
// checkpoint before recreating a missing outbox row.
func (s *Store) ValidateTicketIntakeIntentTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	intent ticketintake.SyncIntent,
) error {
	var sweepID, cursor string
	var readCount int
	var expected *int
	var complete bool
	err := tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, ''), cursor, read_count, expected_count, coverage_complete
		   FROM ticket_intake_schedules
		  WHERE tenant_id = $1 AND system = $2 FOR UPDATE`, tenantID, intent.System).
		Scan(&sweepID, &cursor, &readCount, &expected, &complete)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("store: ticket intake schedule not found")
	}
	if err != nil {
		return err
	}
	if complete || sweepID != intent.SweepID || cursor != intent.Cursor || readCount != intent.ReadCount ||
		!sameOptionalInt(expected, intent.ExpectedCount) {
		return fmt.Errorf("store: ticket intake continuation differs from the durable checkpoint")
	}
	return nil
}
