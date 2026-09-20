// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ownership"
)

// CMDBCIObservation is the bounded, matched subset of one cmdb_ci row kept by
// the projection. It deliberately contains no owner display name or arbitrary
// CMDB attributes: source_ref plus the four contributed values is sufficient
// to make disappearance/reassignment reversible without cloning the CMDB.
type CMDBCIObservation struct {
	SourceRef     string
	OwnerID       string
	ApplicationID string
	Service       string
	BusinessUnit  string
	Environment   string
}

// CMDBSweepPage is the projector-facing form of one immutable page event.
type CMDBSweepPage struct {
	SweepID       string
	AfterSysID    string
	ReadBefore    int
	PageLimit     int
	ObservedAt    time.Time
	Observations  []CMDBCIObservation
	ReadCount     int
	ExpectedCount *int
	Complete      bool
}

// ValidateCMDBSweepIntentTx proves a recovery enqueue is derived from the exact
// incomplete projection checkpoint, not from a stale scheduler copy.
func (s *Store) ValidateCMDBSweepIntentTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	intent ownership.CMDBSyncIntent,
) error {
	var (
		sweepID  string
		after    string
		read     int
		expected *int
		complete bool
	)
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, ''), after_sys_id, read_count, expected_count, coverage_complete
		   FROM cmdb_reconcile_schedules WHERE tenant_id = $1 FOR UPDATE`, tenantID).
		Scan(&sweepID, &after, &read, &expected, &complete); err != nil {
		return err
	}
	if complete || sweepID != intent.SweepID || after != intent.AfterSysID || read != intent.ReadCount ||
		!sameOptionalInt(expected, intent.ExpectedCount) {
		return fmt.Errorf("store: CMDB recovery intent does not match the incomplete checkpoint")
	}
	return nil
}

func sameOptionalInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// CMDBCIObservationsByRefs reloads the immutable page subset needed to verify
// an already-committed signed receipt without re-applying its older ownership
// events after a later page has advanced the same sweep.
func (s *Store) CMDBCIObservationsByRefs(ctx context.Context, tenantID string, refs []string) ([]CMDBCIObservation, error) {
	if len(refs) == 0 {
		return []CMDBCIObservation{}, nil
	}
	if len(refs) > 500 {
		return nil, fmt.Errorf("store: CMDB replay lookup exceeds one page")
	}
	byRef := make(map[string]CMDBCIObservation, len(refs))
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT source_ref, coalesce(owner_id::text, ''), application_id, service, business_unit, environment
			   FROM cmdb_ci_inventory
			  WHERE tenant_id = $1 AND source_ref = ANY($2::text[])`, tenantID, refs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var observation CMDBCIObservation
			if err := rows.Scan(&observation.SourceRef, &observation.OwnerID,
				&observation.ApplicationID, &observation.Service,
				&observation.BusinessUnit, &observation.Environment); err != nil {
				return err
			}
			byRef[observation.SourceRef] = observation
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := make([]CMDBCIObservation, 0, len(refs))
	for _, ref := range refs {
		observation, ok := byRef[ref]
		if !ok {
			return nil, fmt.Errorf("store: committed CMDB page source %q is absent from its inventory", ref)
		}
		out = append(out, observation)
	}
	return out, nil
}

// ApplyCMDBSweepDispatchedTx starts one named sweep. A duplicate replay of the
// same dispatch is a no-op; a different sweep cannot replace incomplete
// coverage. Configuration is the only operation that deliberately resets it.
func (s *Store) ApplyCMDBSweepDispatchedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	intent ownership.CMDBSyncIntent,
	dispatchedAt time.Time,
) error {
	if strings.TrimSpace(intent.SweepID) == "" || intent.AfterSysID != "" || intent.ReadCount != 0 ||
		intent.PageLimit <= 0 || intent.PageLimit > 500 || dispatchedAt.IsZero() {
		return fmt.Errorf("store: invalid initial CMDB sweep checkpoint")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE cmdb_reconcile_schedules
		    SET current_sweep_id = $2::uuid, sweep_started_at = $3, last_attempt_at = $3,
		        after_sys_id = '', read_count = 0, expected_count = $4,
		        pages_completed = 0, coverage_complete = false,
		        removed_count = 0, changed_count = 0, last_error = '', updated_at = now()
		  WHERE tenant_id = $1
		    AND current_sweep_id IS DISTINCT FROM $2::uuid
		    AND (current_sweep_id IS NULL OR coverage_complete)`,
		tenantID, intent.SweepID, dispatchedAt.UTC(), intent.ExpectedCount)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var current string
	err = tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, '')
		   FROM cmdb_reconcile_schedules WHERE tenant_id = $1`, tenantID).Scan(&current)
	if err != nil {
		return err
	}
	if current == intent.SweepID {
		return nil
	}
	return fmt.Errorf("store: CMDB sweep %s cannot replace incomplete sweep %s", intent.SweepID, current)
}

// ApplyCMDBSweepPageObservedTx advances one exact keyset boundary and updates
// its tiny source inventory in the same transaction. The schedule lock is the
// serialization point for concurrent/replayed receipts.
func (s *Store) ApplyCMDBSweepPageObservedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	page CMDBSweepPage,
) error {
	if page.SweepID == "" || page.PageLimit <= 0 || page.PageLimit > 500 || page.ObservedAt.IsZero() ||
		len(page.Observations) > page.PageLimit || page.ReadBefore < 0 ||
		page.ReadCount != page.ReadBefore+len(page.Observations) ||
		(page.Complete && len(page.Observations) >= page.PageLimit) ||
		(!page.Complete && len(page.Observations) != page.PageLimit) {
		return fmt.Errorf("store: invalid bounded CMDB page progress")
	}
	previous := page.AfterSysID
	for _, observation := range page.Observations {
		if !ownership.ValidCMDBSourceRef(observation.SourceRef) || (previous != "" && observation.SourceRef <= previous) {
			return fmt.Errorf("store: CMDB page source refs are not strictly after %q", previous)
		}
		previous = observation.SourceRef
	}

	var (
		currentSweep    string
		currentAfter    string
		currentRead     int
		alreadyComplete bool
	)
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(current_sweep_id::text, ''), after_sys_id, read_count, coverage_complete
		   FROM cmdb_reconcile_schedules
		  WHERE tenant_id = $1
		  FOR UPDATE`, tenantID).Scan(&currentSweep, &currentAfter, &currentRead, &alreadyComplete); err != nil {
		return err
	}
	if currentSweep != page.SweepID {
		return fmt.Errorf("store: CMDB page belongs to sweep %s, current sweep is %s", page.SweepID, currentSweep)
	}
	if alreadyComplete || currentRead > page.ReadCount {
		// Exact receipt/event replay. The immutable event is already reflected;
		// never increment pages or re-run deletion cleanup.
		return nil
	}
	if currentAfter != page.AfterSysID || currentRead != page.ReadBefore {
		return fmt.Errorf("store: CMDB page starts at %q/%d, current checkpoint is %q/%d",
			page.AfterSysID, page.ReadBefore, currentAfter, currentRead)
	}

	for _, observation := range page.Observations {
		if _, err := tx.Exec(ctx,
			`INSERT INTO cmdb_ci_inventory
			   (tenant_id, source_ref, owner_id, application_id, service, business_unit, environment,
			    last_seen_sweep_id, last_seen_at)
			 VALUES ($1, $2, nullif($3, '')::uuid, $4, $5, $6, $7, $8::uuid, $9)
			 ON CONFLICT (tenant_id, source_ref) DO UPDATE SET
			   prior_owner_id = cmdb_ci_inventory.owner_id,
			   prior_present = true,
			   prior_application_id = cmdb_ci_inventory.application_id,
			   prior_service = cmdb_ci_inventory.service,
			   prior_business_unit = cmdb_ci_inventory.business_unit,
			   prior_environment = cmdb_ci_inventory.environment,
			   owner_id = EXCLUDED.owner_id,
			   application_id = EXCLUDED.application_id,
			   service = EXCLUDED.service,
			   business_unit = EXCLUDED.business_unit,
			   environment = EXCLUDED.environment,
			   last_seen_sweep_id = EXCLUDED.last_seen_sweep_id,
			   last_seen_at = EXCLUDED.last_seen_at,
			   removed_at = NULL
			 WHERE cmdb_ci_inventory.last_seen_sweep_id <> EXCLUDED.last_seen_sweep_id`,
			tenantID, observation.SourceRef, observation.OwnerID,
			observation.ApplicationID, observation.Service, observation.BusinessUnit, observation.Environment,
			page.SweepID, page.ObservedAt.UTC()); err != nil {
			return err
		}
	}

	nextCursor := page.AfterSysID
	if len(page.Observations) > 0 {
		nextCursor = page.Observations[len(page.Observations)-1].SourceRef
	}
	removed, changed := int64(0), int64(0)
	if page.Complete {
		// Clear only an unattested value that still points at the exact missing
		// CI and still equals what that CI supplied. Human decisions and later
		// manual edits are therefore never erased by source disappearance.
		if _, err := tx.Exec(ctx,
			`WITH candidates AS (
			   SELECT source_ref, owner_id, application_id, service, business_unit, environment
			     FROM cmdb_ci_inventory
			    WHERE tenant_id = $1 AND last_seen_sweep_id <> $2::uuid
			      AND removed_at IS NULL AND owner_id IS NOT NULL
			   UNION ALL
			   SELECT source_ref, prior_owner_id, prior_application_id, prior_service,
			          prior_business_unit, prior_environment
			     FROM cmdb_ci_inventory
			    WHERE tenant_id = $1 AND last_seen_sweep_id = $2::uuid AND prior_present
			      AND prior_owner_id IS NOT NULL AND prior_owner_id IS DISTINCT FROM owner_id
			 )
			 UPDATE owners AS owner
			    SET application_id = CASE WHEN coalesce(owner.application_id, '') = candidate.application_id THEN NULL ELSE owner.application_id END,
			        service = CASE WHEN coalesce(owner.service, '') = candidate.service THEN NULL ELSE owner.service END,
			        business_unit = CASE WHEN coalesce(owner.business_unit, '') = candidate.business_unit THEN NULL ELSE owner.business_unit END,
			        environment = CASE WHEN coalesce(owner.environment, '') = candidate.environment THEN NULL ELSE owner.environment END,
			        ownership_source = NULL, ownership_source_ref = NULL, ownership_source_observed_at = NULL
			   FROM candidates AS candidate
			  WHERE owner.tenant_id = $1 AND owner.id = candidate.owner_id
			    AND owner.ownership_verified_at IS NULL
			    AND owner.ownership_source = 'cmdb' AND owner.ownership_source_ref = candidate.source_ref
			    AND NOT EXISTS (
			        SELECT 1 FROM cmdb_ci_inventory AS active
			         WHERE active.tenant_id = $1 AND active.last_seen_sweep_id = $2::uuid
			           AND active.owner_id = owner.id AND active.removed_at IS NULL
			    )`, tenantID, page.SweepID); err != nil {
			return err
		}
		removedTag, err := tx.Exec(ctx,
			`UPDATE cmdb_ci_inventory SET removed_at = $3
			  WHERE tenant_id = $1 AND last_seen_sweep_id <> $2::uuid AND removed_at IS NULL`,
			tenantID, page.SweepID, page.ObservedAt.UTC())
		if err != nil {
			return err
		}
		removed = removedTag.RowsAffected()
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM cmdb_ci_inventory
			  WHERE tenant_id = $1 AND last_seen_sweep_id = $2::uuid AND prior_present
			    AND (prior_owner_id IS DISTINCT FROM owner_id
			      OR prior_application_id IS DISTINCT FROM application_id
			      OR prior_service IS DISTINCT FROM service
			      OR prior_business_unit IS DISTINCT FROM business_unit
			      OR prior_environment IS DISTINCT FROM environment)`,
			tenantID, page.SweepID).Scan(&changed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE cmdb_ci_inventory
			    SET prior_owner_id = NULL, prior_present = false, prior_application_id = '',
			        prior_service = '', prior_business_unit = '', prior_environment = ''
			  WHERE tenant_id = $1 AND last_seen_sweep_id = $2::uuid`, tenantID, page.SweepID); err != nil {
			return err
		}
	}

	tag, err := tx.Exec(ctx,
		`UPDATE cmdb_reconcile_schedules
		    SET after_sys_id = $3, read_count = $4, expected_count = $5,
		        pages_completed = pages_completed + 1, coverage_complete = $6,
		        removed_count = CASE WHEN $6 THEN $7 ELSE removed_count END,
		        changed_count = CASE WHEN $6 THEN $8 ELSE changed_count END,
		        last_attempt_at = $9,
		        last_run_at = CASE WHEN $6 THEN $9 ELSE last_run_at END,
		        last_error = '', updated_at = now()
		  WHERE tenant_id = $1 AND current_sweep_id = $2::uuid AND NOT coverage_complete`,
		tenantID, page.SweepID, nextCursor, page.ReadCount, page.ExpectedCount, page.Complete,
		removed, changed, page.ObservedAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: CMDB page lost its current sweep checkpoint")
	}
	return nil
}

// ApplyCMDBSweepFailedTx records a failed attempt without moving its keyset
// cursor or manufacturing last_run_at success.
func (s *Store) ApplyCMDBSweepFailedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, sweepID, afterSysID string,
	failedAt time.Time,
	detail string,
) error {
	if sweepID == "" || failedAt.IsZero() || strings.TrimSpace(detail) == "" {
		return fmt.Errorf("store: invalid CMDB sweep failure")
	}
	_, err := tx.Exec(ctx,
		`UPDATE cmdb_reconcile_schedules
		    SET last_attempt_at = $4, last_error = $5, updated_at = now()
		  WHERE tenant_id = $1 AND current_sweep_id = $2::uuid
		    AND after_sys_id = $3 AND NOT coverage_complete`,
		tenantID, sweepID, afterSysID, failedAt.UTC(), strings.TrimSpace(detail))
	return err
}
