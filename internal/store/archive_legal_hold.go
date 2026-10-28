// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ArchiveLegalHold is a person's S3 legal hold on one archive object (A208).
// Pending until the outbox has set it in the bucket and read it back; then
// applied. A release is pending until the bucket reads it cleared.
type ArchiveLegalHold struct {
	TenantID      string
	ID            string
	Object        string
	Reason        string
	ReportRunID   string
	PlacedBy      string
	PlacedAt      time.Time
	Status        string
	StatusDetail  string
	AppliedAt     *time.Time
	ReleasedAt    *time.Time
	UpdatedAt     time.Time
	EventSequence uint64
}

// Active reports whether the hold is placed and not yet released or failed.
func (h ArchiveLegalHold) Active() bool {
	return h.Status == "pending" || h.Status == "applied" || h.Status == "release_pending"
}

// ArchiveLegalHoldDestination is the outbox destination that sets or clears a
// legal hold in the bucket.
const ArchiveLegalHoldDestination = "archive.legal_hold.set"

// ArchiveLegalHoldEffect is the outbox payload.
type ArchiveLegalHoldEffect struct {
	ID     string `json:"id"`
	Object string `json:"object"`
	On     bool   `json:"on"`
}

// ErrArchiveLegalHoldState is a change the hold's state does not allow: a
// second active hold on one object, or releasing a hold that is not active.
// Commands refuse it before they record anything; the projections themselves
// treat such an event as a no-op, so a race can never leave an event that does
// not project.
var ErrArchiveLegalHoldState = errors.New("store: the archive legal hold's state does not allow that")

// PlaceArchiveLegalHoldTx records a placed hold and queues setting it in the
// bucket, in the projecting transaction. A replay, or a placement that lost a
// race to another active hold on the object, changes nothing.
func (s *Store) PlaceArchiveLegalHoldTx(ctx context.Context, tx pgx.Tx, h ArchiveLegalHold) error {
	var existing int64
	err := tx.QueryRow(ctx, `SELECT event_sequence FROM archive_legal_holds WHERE tenant_id = $1 AND id = $2`,
		h.TenantID, h.ID).Scan(&existing)
	switch {
	case err == nil:
		return nil // a replay of the placement
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	var active bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM archive_legal_holds WHERE tenant_id = $1 AND object = $2
		                  AND status IN ('pending', 'applied', 'release_pending'))`,
		h.TenantID, h.Object).Scan(&active); err != nil {
		return err
	}
	if active {
		return nil
	}
	var runID any
	if h.ReportRunID != "" {
		runID = h.ReportRunID
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO archive_legal_holds (tenant_id, id, object, reason, report_run_id, placed_by, placed_at, status,
		                                  updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $7, $8)`,
		h.TenantID, h.ID, h.Object, h.Reason, runID, h.PlacedBy, h.PlacedAt,
		int64(h.EventSequence)); err != nil { // #nosec G115 -- event sequences fit int64 (CWE-190)
		return err
	}
	return queueArchiveLegalHoldEffectTx(ctx, tx, h.TenantID, h.ID, h.Object, true, h.EventSequence)
}

// RequestArchiveLegalHoldReleaseTx moves an active hold to release_pending and
// queues clearing it in the bucket. A replay, or a release of a hold that is
// no longer pending or applied, changes nothing.
func (s *Store) RequestArchiveLegalHoldReleaseTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time, sequence uint64) error {
	current, err := lockArchiveLegalHoldTx(ctx, tx, tenantID, id)
	if err != nil {
		return err
	}
	if current.EventSequence >= sequence {
		return nil
	}
	if current.Status != "pending" && current.Status != "applied" {
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE archive_legal_holds SET status = 'release_pending', updated_at = $3, event_sequence = $4
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, int64(sequence)); err != nil { // #nosec G115 -- event sequences fit int64 (CWE-190)
		return err
	}
	return queueArchiveLegalHoldEffectTx(ctx, tx, tenantID, id, current.Object, false, sequence)
}

// RecordArchiveLegalHoldOutcomeTx records what the bucket read back: applied
// (a placement), released (a release) or failed with the reason. A replay, or
// an outcome for a step the hold has already left, changes nothing.
func (s *Store) RecordArchiveLegalHoldOutcomeTx(ctx context.Context, tx pgx.Tx, tenantID, id, status, detail string, at time.Time, sequence uint64) error {
	current, err := lockArchiveLegalHoldTx(ctx, tx, tenantID, id)
	if err != nil {
		return err
	}
	if current.EventSequence >= sequence {
		return nil
	}
	switch {
	case status == "applied" && current.Status == "pending":
		_, err = tx.Exec(ctx, `UPDATE archive_legal_holds SET status = 'applied', status_detail = '', applied_at = $3,
		                         updated_at = $3, event_sequence = $4 WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	case status == "released" && current.Status == "release_pending":
		_, err = tx.Exec(ctx, `UPDATE archive_legal_holds SET status = 'released', status_detail = '', released_at = $3,
		                         updated_at = $3, event_sequence = $4 WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	case status == "failed" && current.Active():
		_, err = tx.Exec(ctx, `UPDATE archive_legal_holds SET status = 'failed', status_detail = $3, updated_at = $4,
		                         event_sequence = $5 WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, detail, at, int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	}
	return err
}

func queueArchiveLegalHoldEffectTx(ctx context.Context, tx pgx.Tx, tenantID, id, object string, on bool, sequence uint64) error {
	payload, err := json.Marshal(ArchiveLegalHoldEffect{ID: id, Object: object, On: on})
	if err != nil {
		return err
	}
	key := "archive-legal-hold:" + id + ":off"
	if on {
		key = "archive-legal-hold:" + id + ":on"
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2)`,
		tenantID, key).Scan(&exists); err != nil || exists {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $2, $3, $4)`, tenantID, ArchiveLegalHoldDestination, payload, key)
	return err
}

const archiveLegalHoldColumns = `tenant_id::text, id::text, object, reason, coalesce(report_run_id::text, ''), placed_by,
        placed_at, status, status_detail, applied_at, released_at, updated_at, event_sequence`

func scanArchiveLegalHold(row pgx.Row, h *ArchiveLegalHold) error {
	var seq int64
	if err := row.Scan(&h.TenantID, &h.ID, &h.Object, &h.Reason, &h.ReportRunID, &h.PlacedBy, &h.PlacedAt, &h.Status,
		&h.StatusDetail, &h.AppliedAt, &h.ReleasedAt, &h.UpdatedAt, &seq); err != nil {
		return err
	}
	h.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
	return nil
}

func lockArchiveLegalHoldTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (ArchiveLegalHold, error) {
	var h ArchiveLegalHold
	err := scanArchiveLegalHold(tx.QueryRow(ctx,
		`SELECT `+archiveLegalHoldColumns+` FROM archive_legal_holds WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID, id), &h)
	return h, err
}

// GetArchiveLegalHold returns one hold.
func (s *Store) GetArchiveLegalHold(ctx context.Context, tenantID, id string) (ArchiveLegalHold, error) {
	var h ArchiveLegalHold
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanArchiveLegalHold(tx.QueryRow(ctx,
			`SELECT `+archiveLegalHoldColumns+` FROM archive_legal_holds WHERE tenant_id = $1 AND id = $2`, tenantID, id), &h)
	})
	return h, err
}

// ActiveArchiveLegalHoldFor returns the object's active hold, if any.
func (s *Store) ActiveArchiveLegalHoldFor(ctx context.Context, tenantID, object string) (ArchiveLegalHold, bool, error) {
	var h ArchiveLegalHold
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanArchiveLegalHold(tx.QueryRow(ctx,
			`SELECT `+archiveLegalHoldColumns+` FROM archive_legal_holds
			  WHERE tenant_id = $1 AND object = $2 AND status IN ('pending', 'applied', 'release_pending')`,
			tenantID, object), &h)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ArchiveLegalHold{}, false, nil
	}
	return h, err == nil, err
}

// ListArchiveLegalHolds returns the tenant's holds, newest first, at most limit.
func (s *Store) ListArchiveLegalHolds(ctx context.Context, tenantID string, limit int) ([]ArchiveLegalHold, error) {
	if limit < 1 || limit > 500 {
		return nil, errors.New("store: archive legal hold list limit must be 1-500")
	}
	var out []ArchiveLegalHold
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+archiveLegalHoldColumns+` FROM archive_legal_holds WHERE tenant_id = $1
			  ORDER BY placed_at DESC, id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h ArchiveLegalHold
			if err := scanArchiveLegalHold(rows, &h); err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}

// ArchiveLegalHoldsForReportRuns returns, per report run, the latest storage
// hold a report legal hold placed on its object.
func (s *Store) ArchiveLegalHoldsForReportRuns(ctx context.Context, tenantID string, runIDs []string) (map[string]ArchiveLegalHold, error) {
	out := make(map[string]ArchiveLegalHold, len(runIDs))
	if len(runIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (report_run_id) `+archiveLegalHoldColumns+` FROM archive_legal_holds
			  WHERE tenant_id = $1 AND report_run_id = ANY($2::uuid[])
			  ORDER BY report_run_id, placed_at DESC, id`, tenantID, runIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h ArchiveLegalHold
			if err := scanArchiveLegalHold(rows, &h); err != nil {
				return err
			}
			out[h.ReportRunID] = h
		}
		return rows.Err()
	})
	return out, err
}
