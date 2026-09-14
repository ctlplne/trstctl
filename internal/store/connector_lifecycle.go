// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ConnectorDeliveryReceipt is the projected evidence for one connector.deploy
// outbox row. It deliberately contains no certificate or private-key bytes.
type ConnectorDeliveryReceipt struct {
	// EventSequence comes from the authoritative envelope, never the event payload.
	EventSequence  uint64
	ID             string
	TenantID       string
	OutboxID       *int64
	IdentityID     *string
	Destination    string
	Connector      string
	Target         string
	Fingerprint    string
	Status         string
	Attempts       int
	Reason         string
	Detail         string
	RollbackRef    string
	IdempotencyKey string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RotationRun is the projected evidence for one lifecycle renewal/rotation
// outbox row, including enough rollback metadata for an operator to tie the
// successor back to the retired public certificate.
type RotationRun struct {
	ID                       string
	TenantID                 string
	IdentityID               string
	OutboxID                 *int64
	Status                   string
	Trigger                  string
	Reason                   string
	PredecessorFingerprint   string
	SuccessorFingerprint     string
	RollbackRef              string
	Error                    string
	IdempotencyKey           string
	CreatedAt                time.Time
	UpdatedAt                time.Time
	CompletedAt              *time.Time
	FirstEventSequence       uint64
	LatestEventSequence      uint64
	LegacyPredecessorBinding bool
}

// ApplyConnectorDeliveryRecordedTx projects a connector.delivery.recorded event.
// Repeated attempts for the same delivery id update the same row, so retries
// converge instead of creating misleading duplicate receipts.
func (s *Store) ApplyConnectorDeliveryRecordedTx(ctx context.Context, tx pgx.Tx, r ConnectorDeliveryReceipt) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO connector_delivery_receipts
		        (id, tenant_id, outbox_id, identity_id, destination, connector, target,
		         fingerprint, status, attempts, reason, detail, rollback_ref,
		         idempotency_key, created_at, updated_at, latest_event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		 ON CONFLICT DO NOTHING`,
		r.ID, r.TenantID, r.OutboxID, r.IdentityID, r.Destination, r.Connector, r.Target,
		r.Fingerprint, r.Status, r.Attempts, r.Reason, r.Detail, r.RollbackRef,
		r.IdempotencyKey, r.CreatedAt, r.UpdatedAt, r.EventSequence)
	if err != nil {
		return err
	}
	// One outbox command has one receipt even when a retry constructs a fresh
	// receipt UUID. Converge through (tenant, outbox) when present; id is the
	// fallback natural key for receipts without an outbox row.
	tag, err := tx.Exec(ctx,
		`UPDATE connector_delivery_receipts
		    SET outbox_id = $3,
		        identity_id = $4,
		        destination = $5,
		        connector = $6,
		        target = $7,
		        fingerprint = $8,
		        status = $9,
		        attempts = $10,
		        reason = $11,
		        detail = $12,
		        rollback_ref = $13,
		        idempotency_key = $14,
		        updated_at = $15,
          latest_event_sequence = $16
		  WHERE tenant_id = $2
		    AND (($3::bigint IS NOT NULL AND outbox_id = $3)
		      OR ($3::bigint IS NULL AND id = $1))
        AND coalesce(latest_event_sequence, 0) <= $16`,
		r.ID, r.TenantID, r.OutboxID, r.IdentityID, r.Destination, r.Connector, r.Target,
		r.Fingerprint, r.Status, r.Attempts, r.Reason, r.Detail, r.RollbackRef,
		r.IdempotencyKey, r.UpdatedAt, r.EventSequence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// An earlier attempt can arrive from the durable tail after a newer inline
	// result. Preserve its history without hiding a recovered delivery or rearm.
	var newer bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connector_delivery_receipts
   WHERE tenant_id=$1 AND (($2::bigint IS NOT NULL AND outbox_id=$2) OR ($2::bigint IS NULL AND id=$3))
   AND coalesce(latest_event_sequence,0) > $4)`, r.TenantID, r.OutboxID, r.ID, r.EventSequence).Scan(&newer); err != nil {
		return err
	}
	if newer {
		return nil
	}
	var existingOutbox sql.NullInt64
	queryErr := tx.QueryRow(ctx,
		`SELECT outbox_id FROM connector_delivery_receipts WHERE tenant_id = $1 AND id = $2`,
		r.TenantID, r.ID).Scan(&existingOutbox)
	if queryErr == nil {
		return fmt.Errorf("connector delivery receipt reuses id %s for a different outbox command", r.ID)
	}
	if queryErr != pgx.ErrNoRows {
		return queryErr
	}
	return fmt.Errorf("connector delivery receipt id %s conflicts outside tenant %s or references an unavailable row", r.ID, r.TenantID)
}

// ApplyRotationRunRecordedTx projects a lifecycle.rotation.recorded event.
func (s *Store) ApplyRotationRunRecordedTx(ctx context.Context, tx pgx.Tx, r RotationRun) error {
	if r.FirstEventSequence == 0 {
		r.FirstEventSequence = r.LatestEventSequence
	}
	if r.LatestEventSequence == 0 {
		r.LatestEventSequence = r.FirstEventSequence
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO lifecycle_rotation_runs
		        (id, tenant_id, identity_id, outbox_id, status, trigger, reason,
		         predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
		         idempotency_key, created_at, updated_at, completed_at,
		         first_event_sequence, latest_event_sequence, legacy_predecessor_binding)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		 ON CONFLICT DO NOTHING`,
		r.ID, r.TenantID, r.IdentityID, r.OutboxID, r.Status, r.Trigger, r.Reason,
		r.PredecessorFingerprint, r.SuccessorFingerprint, r.RollbackRef, r.Error,
		r.IdempotencyKey, r.CreatedAt, r.UpdatedAt, r.CompletedAt,
		nullableRotationEventSequence(r.FirstEventSequence), nullableRotationEventSequence(r.LatestEventSequence),
		r.LegacyPredecessorBinding)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// A lifecycle observation has two legitimate identities. An exact tail
	// replay finds the payload UUID; a separately-created observation for the
	// same external operation finds (tenant_id, outbox_id). ON CONFLICT cannot
	// safely name only one of those indexes: the inline projector and durable
	// tail can race, and PostgreSQL is allowed to observe the other index first.
	// Lock every tenant-local candidate, reject a split identity, then reconcile
	// the one winner after validating the immutable command binding.
	rows, err := tx.Query(ctx,
		`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
		        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
		        idempotency_key, created_at, updated_at, completed_at,
		        first_event_sequence, latest_event_sequence, legacy_predecessor_binding
		   FROM lifecycle_rotation_runs
		  WHERE tenant_id = $1
		    AND (id = $2 OR ($3::bigint IS NOT NULL AND outbox_id = $3))
		  ORDER BY id
		  FOR UPDATE`,
		r.TenantID, r.ID, r.OutboxID)
	if err != nil {
		return err
	}
	var matches []RotationRun
	for rows.Next() {
		var existing RotationRun
		if err := scanRotationRun(rows, &existing); err != nil {
			rows.Close()
			return err
		}
		matches = append(matches, existing)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if len(matches) != 1 {
		return fmt.Errorf(
			"%w: lifecycle rotation tenant=%s incoming_id=%s matched %d rows across id/outbox identities",
			ErrIdempotencyConflict, r.TenantID, r.ID, len(matches),
		)
	}
	existing := matches[0]
	if differences := rotationRunBindingDifferences(existing, r); len(differences) > 0 {
		return fmt.Errorf(
			"%w: lifecycle rotation tenant=%s existing_id=%s incoming_id=%s differing_binding_fields=%s",
			ErrIdempotencyConflict, r.TenantID, existing.ID, r.ID, strings.Join(differences, ","),
		)
	}

	desired := existing
	if desired.FirstEventSequence == 0 && r.FirstEventSequence > 0 {
		// A pre-0143 row has no historical sequence columns. The first live
		// post-upgrade observation starts its ordered epoch without rewriting
		// the row's already-established canonical ID or created_at.
		desired.FirstEventSequence = r.FirstEventSequence
	}
	if desired.LatestEventSequence == 0 && rotationRunIsLegacyHistoricalReplay(r, existing) {
		// The upgraded row may already contain the terminal result while the
		// durable tail starts again at an older event. Enter the ordered epoch at
		// that historical event without pulling the retained terminal result
		// backwards; later replayed events advance latest_event_sequence normally.
		desired.LatestEventSequence = r.LatestEventSequence
	}
	if rotationRunPrecedes(r, existing) {
		desired.ID = r.ID
		desired.CreatedAt = r.CreatedAt
		desired.FirstEventSequence = r.FirstEventSequence
	}
	observationOrder, sequenceOrdered := rotationRunObservationOrder(r, existing)
	if observationOrder > 0 && r.UpdatedAt.After(desired.UpdatedAt) {
		desired.UpdatedAt = r.UpdatedAt
	}

	switch {
	case observationOrder < 0:
		// An inline writer may already have committed a newer observation when
		// the durable tail reaches this older stream sequence. Keep the newer
		// state even when the older producer clock appears later.
	case observationOrder > 0:
		if err := applyLaterRotationRunObservation(&desired, r); err != nil {
			return fmt.Errorf(
				"%w: lifecycle rotation tenant=%s existing_id=%s incoming_id=%s %v",
				ErrIdempotencyConflict, r.TenantID, existing.ID, r.ID, err,
			)
		}
		desired.LatestEventSequence = r.LatestEventSequence
	default:
		differences := rotationRunObservationDifferences(existing, r)
		if len(differences) == 0 {
			break
		}
		if sequenceOrdered {
			return fmt.Errorf(
				"%w: lifecycle rotation tenant=%s existing_id=%s incoming_id=%s differing_same_sequence_fields=%s",
				ErrIdempotencyConflict, r.TenantID, existing.ID, r.ID, strings.Join(differences, ","),
			)
		}
		existingTerminal := rotationRunStatusTerminal(existing.Status)
		incomingTerminal := rotationRunStatusTerminal(r.Status)
		switch {
		case !existingTerminal && incomingTerminal:
			// PostgreSQL stores microseconds. Two successive event timestamps can
			// therefore tie after encoding; in that tie only the terminal state
			// may advance the row.
			applyRotationRunObservation(&desired, r)
		case existingTerminal && !incomingTerminal:
			// The same precision tie cannot pull a terminal row backwards.
		default:
			return fmt.Errorf(
				"%w: lifecycle rotation tenant=%s existing_id=%s incoming_id=%s differing_same_time_fields=%s",
				ErrIdempotencyConflict, r.TenantID, existing.ID, r.ID, strings.Join(differences, ","),
			)
		}
	}

	tag, err = tx.Exec(ctx,
		`UPDATE lifecycle_rotation_runs
		    SET id = $3,
		        status = $4,
		        successor_fingerprint = $5,
		        rollback_ref = $6,
		        error = $7,
		        created_at = $8,
		        updated_at = $9,
		        completed_at = $10,
		        first_event_sequence = $11,
		        latest_event_sequence = $12
		  WHERE tenant_id = $1 AND id = $2`,
		r.TenantID, existing.ID, desired.ID, desired.Status, desired.SuccessorFingerprint,
		desired.RollbackRef, desired.Error, desired.CreatedAt, desired.UpdatedAt, desired.CompletedAt,
		nullableRotationEventSequence(desired.FirstEventSequence), nullableRotationEventSequence(desired.LatestEventSequence))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: lifecycle rotation canonical row identity is already bound", ErrIdempotencyConflict)
		}
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: lifecycle rotation row disappeared during reconciliation", ErrIdempotencyConflict)
	}
	return nil
}

func rotationRunBindingDifferences(existing, incoming RotationRun) []string {
	differences := make([]string, 0, 6)
	if existing.IdentityID != incoming.IdentityID {
		differences = append(differences, "identity_id")
	}
	if !sameOptionalInt64(existing.OutboxID, incoming.OutboxID) {
		differences = append(differences, "outbox_id")
	}
	if existing.Trigger != incoming.Trigger {
		differences = append(differences, "trigger")
	}
	if existing.Reason != incoming.Reason {
		differences = append(differences, "reason")
	}
	// Migration 0194 marks only rows that existed before ordered replay was
	// introduced. Some v0.5.x lifecycle events omitted this optional public
	// fingerprint even though the old inline projector retained it in the row.
	// Treat that one missing historical field as unknown, never as an empty
	// replacement. Every new row remains strict, and a non-empty mismatch is
	// always rejected.
	legacyMissingPredecessor := existing.LegacyPredecessorBinding &&
		existing.ID == incoming.ID && incoming.PredecessorFingerprint == ""
	if existing.PredecessorFingerprint != incoming.PredecessorFingerprint && !legacyMissingPredecessor {
		differences = append(differences, "predecessor_fingerprint")
	}
	if existing.IdempotencyKey != incoming.IdempotencyKey {
		differences = append(differences, "idempotency_key")
	}
	return differences
}

func rotationRunObservationDifferences(existing, incoming RotationRun) []string {
	differences := make([]string, 0, 5)
	if existing.Status != incoming.Status {
		differences = append(differences, "status")
	}
	if existing.SuccessorFingerprint != incoming.SuccessorFingerprint {
		differences = append(differences, "successor_fingerprint")
	}
	if existing.RollbackRef != incoming.RollbackRef {
		differences = append(differences, "rollback_ref")
	}
	if existing.Error != incoming.Error {
		differences = append(differences, "error")
	}
	if !sameOptionalTime(existing.CompletedAt, incoming.CompletedAt) {
		differences = append(differences, "completed_at")
	}
	return differences
}

func sameOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	// PostgreSQL timestamptz and pgx retain microseconds. Ignore only the
	// sub-microsecond bits an immutable event cannot recover after its first
	// projection; one retained microsecond still represents different evidence.
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

func rotationRunStatusTerminal(status string) bool {
	return status == "succeeded" || status == "failed" || status == "cancelled"
}

func applyLaterRotationRunObservation(destination *RotationRun, source RotationRun) error {
	differences := rotationRunObservationDifferences(*destination, source)
	if len(differences) == 0 {
		return nil
	}
	if destination.Status == "cancelled" && (source.Status == "running" || source.Status == "failed") {
		// An already-issued failure callback can trail the stop event. Preserve
		// that event in the audit log without re-arming cancelled work.
		return nil
	}
	if destination.Status == "succeeded" || destination.Status == "cancelled" {
		return fmt.Errorf("completed evidence is final; differing_fields=%s", strings.Join(differences, ","))
	}
	if destination.Status == "running" && source.Status == "running" {
		return fmt.Errorf("a later running observation changed outcome fields=%s", strings.Join(differences, ","))
	}
	applyRotationRunObservation(destination, source)
	return nil
}

func applyRotationRunObservation(destination *RotationRun, source RotationRun) {
	destination.Status = source.Status
	destination.SuccessorFingerprint = source.SuccessorFingerprint
	destination.RollbackRef = source.RollbackRef
	destination.Error = source.Error
	destination.CompletedAt = source.CompletedAt
}

func rotationRunPrecedes(candidate, existing RotationRun) bool {
	if candidate.FirstEventSequence > 0 && existing.FirstEventSequence > 0 {
		return candidate.FirstEventSequence < existing.FirstEventSequence
	}
	if candidate.FirstEventSequence == 0 && existing.FirstEventSequence > 0 {
		return false
	}
	if candidate.CreatedAt.IsZero() {
		return false
	}
	order := rotationRunTimeOrder(candidate.CreatedAt, existing.CreatedAt)
	if existing.CreatedAt.IsZero() || order < 0 {
		return true
	}
	return order == 0 && candidate.ID < existing.ID
}

// rotationRunObservationOrder compares the local immutable stream order when
// both observations carry it. New events always do; the timestamp fallback is
// only for pre-0143 rows and direct legacy callers that have no sequence.
func rotationRunObservationOrder(candidate, existing RotationRun) (order int, sequenceOrdered bool) {
	if candidate.LatestEventSequence > 0 && existing.LatestEventSequence > 0 {
		switch {
		case candidate.LatestEventSequence < existing.LatestEventSequence:
			return -1, true
		case candidate.LatestEventSequence > existing.LatestEventSequence:
			return 1, true
		default:
			return 0, true
		}
	}
	if candidate.LatestEventSequence > 0 && existing.LatestEventSequence == 0 {
		if rotationRunIsLegacyHistoricalReplay(candidate, existing) {
			return rotationRunTimeOrder(candidate.UpdatedAt, existing.UpdatedAt), false
		}
		// A live post-upgrade event follows a legacy row whose checkpoint had
		// already covered its history. Adopt the real local order from here on.
		return 1, false
	}
	if candidate.LatestEventSequence == 0 && existing.LatestEventSequence > 0 {
		// A sequence-less legacy/direct caller cannot supersede a row that has
		// entered the ordered epoch.
		return -1, true
	}
	return rotationRunTimeOrder(candidate.UpdatedAt, existing.UpdatedAt), false
}

func rotationRunIsLegacyHistoricalReplay(candidate, existing RotationRun) bool {
	return existing.LegacyPredecessorBinding && candidate.ID == existing.ID &&
		candidate.LatestEventSequence > 0 && !candidate.UpdatedAt.After(existing.UpdatedAt)
}

func nullableRotationEventSequence(sequence uint64) sql.NullInt64 {
	return sql.NullInt64{
		Int64: int64(sequence), // #nosec G115 -- JetStream sequence fits PostgreSQL bigint by construction (CWE-190)
		Valid: sequence > 0,
	}
}

func rotationRunTimeOrder(candidate, existing time.Time) int {
	candidateMicros := candidate.UnixMicro()
	existingMicros := existing.UnixMicro()
	if candidateMicros < existingMicros {
		return -1
	}
	if candidateMicros > existingMicros {
		return 1
	}
	return 0
}

func scanConnectorDeliveryReceipt(row pgx.Row, r *ConnectorDeliveryReceipt) error {
	var (
		outboxID   sql.NullInt64
		identityID sql.NullString
	)
	err := row.Scan(&r.ID, &r.TenantID, &outboxID, &identityID, &r.Destination, &r.Connector,
		&r.Target, &r.Fingerprint, &r.Status, &r.Attempts, &r.Reason, &r.Detail,
		&r.RollbackRef, &r.IdempotencyKey, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return err
	}
	if outboxID.Valid {
		r.OutboxID = &outboxID.Int64
	}
	if identityID.Valid {
		r.IdentityID = &identityID.String
	}
	return nil
}

func scanRotationRun(row pgx.Row, r *RotationRun) error {
	var (
		outboxID            sql.NullInt64
		firstEventSequence  sql.NullInt64
		latestEventSequence sql.NullInt64
	)
	err := row.Scan(&r.ID, &r.TenantID, &r.IdentityID, &outboxID, &r.Status, &r.Trigger, &r.Reason,
		&r.PredecessorFingerprint, &r.SuccessorFingerprint, &r.RollbackRef, &r.Error,
		&r.IdempotencyKey, &r.CreatedAt, &r.UpdatedAt, &r.CompletedAt,
		&firstEventSequence, &latestEventSequence, &r.LegacyPredecessorBinding)
	if err != nil {
		return err
	}
	if outboxID.Valid {
		r.OutboxID = &outboxID.Int64
	}
	if firstEventSequence.Valid && firstEventSequence.Int64 > 0 {
		r.FirstEventSequence = uint64(firstEventSequence.Int64) // #nosec G115 -- constrained positive PostgreSQL bigint (CWE-190)
	}
	if latestEventSequence.Valid && latestEventSequence.Int64 > 0 {
		r.LatestEventSequence = uint64(latestEventSequence.Int64) // #nosec G115 -- constrained positive PostgreSQL bigint (CWE-190)
	}
	return nil
}

// ListConnectorDeliveryReceiptsPage returns delivery receipts for one tenant.
func (s *Store) ListConnectorDeliveryReceiptsPage(ctx context.Context, tenantID, identityID, afterID string, limit int) ([]ConnectorDeliveryReceipt, error) {
	return s.ListConnectorDeliveryReceiptsMatchingPage(ctx, tenantID, identityID, "", afterID, limit)
}

// ListConnectorDeliveryReceiptsMatchingPage optionally filters by the exact
// receipt key, so an asynchronous result does not depend on a global history page.
func (s *Store) ListConnectorDeliveryReceiptsMatchingPage(ctx context.Context, tenantID, identityID, key, afterID string, limit int) ([]ConnectorDeliveryReceipt, error) {
	var out []ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			        connector, target, fingerprint, status, attempts, reason, detail,
			        rollback_ref, idempotency_key, created_at, updated_at
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR identity_id::text = $3)
			    AND ($5 = '' OR idempotency_key = $5)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, identityID, limit, key)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ConnectorDeliveryReceipt
			if err := scanConnectorDeliveryReceipt(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListConnectorDeliveryReceiptsNewestPage returns the newest receipt activity
// first. The composite cursor stays fixed if its receipt changes or is erased;
// fresh activity appears when the operator refreshes the first page.
func (s *Store) ListConnectorDeliveryReceiptsNewestPage(ctx context.Context, tenantID, identityID, key, afterID string, afterUpdatedAt *time.Time, limit int) ([]ConnectorDeliveryReceipt, error) {
	var out []ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			        connector, target, fingerprint, status, attempts, reason, detail,
			        rollback_ref, idempotency_key, created_at, updated_at
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1
			    AND ($6::timestamptz IS NULL OR (updated_at, id) < ($6, $2::uuid))
			    AND ($3 = '' OR identity_id::text = $3)
			    AND ($5 = '' OR idempotency_key = $5)
			  ORDER BY updated_at DESC, connector_delivery_receipts.id DESC
			  LIMIT $4`, tenantID, afterID, identityID, limit, key, afterUpdatedAt)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ConnectorDeliveryReceipt
			if err := scanConnectorDeliveryReceipt(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// LatestDeployedCertificateFingerprintForIdentity returns the exact public
// certificate fingerprint most recently proved on the wire for one identity.
//
// Owner plus DNS name is not an identity key: a retained estate can contain
// several independent identities for the same service name and owner. Renewal
// must follow the identity-bound delivery evidence or it can replace a
// different certificate that merely has the same SAN. Issued active rows are
// eligible; a superseded row requires proved rollback evidence, because issuance
// history does not change when an executor restores it. Revoked rows are never
// eligible. Queued and failed restores do not change the served evidence.
func (s *Store) LatestDeployedCertificateFingerprintForIdentity(ctx context.Context, tenantID, identityID string) (string, bool, error) {
	var fingerprint string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT r.fingerprint
			   FROM connector_delivery_receipts r
			   JOIN certificates c
			     ON c.tenant_id = r.tenant_id
			    AND c.fingerprint = r.fingerprint
			  WHERE r.tenant_id = $1
			    AND r.identity_id = $2
			    AND ((r.destination = 'connector.deploy' AND r.status IN ('delivered', 'verified') AND c.status = 'active')
			      OR (r.destination = 'connector.rollback' AND r.status = 'rolled_back' AND c.status IN ('active', 'superseded')))
			    AND c.source = 'issued'
			  ORDER BY r.updated_at DESC, r.id DESC
			  LIMIT 1`, tenantID, identityID).Scan(&fingerprint)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return fingerprint, err == nil, err
}

// GetConnectorDeliveryReceiptForOutboxTx resolves the canonical projected row
// while the caller still owns the transaction that queued the command.
func (s *Store) GetConnectorDeliveryReceiptForOutboxTx(ctx context.Context, tx pgx.Tx, tenantID string, outboxID int64) (ConnectorDeliveryReceipt, error) {
	var r ConnectorDeliveryReceipt
	err := scanConnectorDeliveryReceipt(tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
		        connector, target, fingerprint, status, attempts, reason, detail,
		        rollback_ref, idempotency_key, created_at, updated_at
		   FROM connector_delivery_receipts
		  WHERE tenant_id = $1 AND outbox_id = $2`, tenantID, outboxID), &r)
	return r, err
}

// GetConnectorDeliveryReceipt loads one receipt in its tenant context.
func (s *Store) GetConnectorDeliveryReceipt(ctx context.Context, tenantID, id string) (ConnectorDeliveryReceipt, error) {
	var r ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanConnectorDeliveryReceipt(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			        connector, target, fingerprint, status, attempts, reason, detail,
			        rollback_ref, idempotency_key, created_at, updated_at
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}

// ListRotationRunsPage returns rotation/renewal runs for one tenant.
func (s *Store) ListRotationRunsPage(ctx context.Context, tenantID, identityID, afterID string, limit int) ([]RotationRun, error) {
	var out []RotationRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
			        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
			        idempotency_key, created_at, updated_at, completed_at,
			        first_event_sequence, latest_event_sequence, legacy_predecessor_binding
			   FROM lifecycle_rotation_runs
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR identity_id::text = $3)
			  ORDER BY id
			  LIMIT $4`, tenantID, afterID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r RotationRun
			if err := scanRotationRun(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetRotationRun loads one lifecycle rotation run in its tenant context.
func (s *Store) GetRotationRun(ctx context.Context, tenantID, id string) (RotationRun, error) {
	var r RotationRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRotationRun(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
			        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
			        idempotency_key, created_at, updated_at, completed_at,
			        first_event_sequence, latest_event_sequence, legacy_predecessor_binding
			   FROM lifecycle_rotation_runs
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &r)
	})
	return r, err
}

// ListRenewableIdentities returns deployed X.509 identities whose active served
// certificates expire before cutoff. The scheduler uses this to queue the normal
// deployed->renewing transition, so renewal still travels through the outbox.
// Renewal candidates include renewal_failed as well as deployed. That state
// exists so a failed renewal can be RECORDED without re-deploying a certificate
// that was never renewed or revoking a valid one; if the scheduler then ignored
// it, the identity would simply be stuck somewhere new instead of stuck in
// renewing, which would defeat the point of adding the state.
func (s *Store) ListRenewableIdentities(ctx context.Context, tenantID string, cutoff time.Time) ([]Identity, error) {
	var out []Identity
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (i.id) i.id::text, i.tenant_id::text, i.kind, i.name, i.owner_id::text,
			        i.issuer_id::text, i.status, i.not_before, i.not_after, i.attributes, i.created_at
			   FROM identities i
			   JOIN certificates c
			     ON c.tenant_id = i.tenant_id
			    AND c.owner_id = i.owner_id
			    AND i.name = ANY(c.sans)
			  WHERE i.tenant_id = $1
			    AND i.kind = 'x509_certificate'
			    AND i.status IN ('deployed', 'renewal_failed')
			    AND NOT EXISTS (SELECT 1 FROM identities replacement
			      WHERE replacement.tenant_id = i.tenant_id
			        AND replacement.attributes->>'endpoint_replaces_identity_id' = i.id::text
			        AND replacement.status IN ('issued', 'deployed', 'renewing', 'renewal_failed'))
			    AND c.source = 'issued'
			    AND c.status = 'active'
			    AND c.not_after IS NOT NULL
			    AND c.not_after < $2
			  ORDER BY i.id, i.created_at`, tenantID, cutoff)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				it    Identity
				kind  string
				attrs []byte
			)
			if err := rows.Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt); err != nil {
				return err
			}
			it.Kind = IdentityKind(kind)
			it.Attributes = attrs
			out = append(out, it)
		}
		return rows.Err()
	})
	return out, err
}

// RenewalIdentityCandidate is the scheduler input for one deployed X.509
// identity and the issued active or proved-restored certificate that makes it renewable.
// The server consumes the certificate validity span through the ARI package, so
// the renewal decision stays aligned with ACME Renewal Information rather than a
// fixed expiry cutoff alone.
type RenewalIdentityCandidate struct {
	Identity    Identity
	Certificate Certificate
}

// ListRenewalIdentityCandidates returns deployed X.509 identities whose active or restored
// served certificates are eligible for a scheduler decision. Eligibility is a
// coarse database prefilter: either the old fixed cutoff is already reached, or
// the normal ARI suggested-window start has reached ariNow. The server still
// recomputes the final decision with internal/protocols/ari before mutating
// lifecycle state.
func (s *Store) ListRenewalIdentityCandidates(ctx context.Context, tenantID string, fixedCutoff, ariNow time.Time) ([]RenewalIdentityCandidate, error) {
	var out []RenewalIdentityCandidate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT DISTINCT ON (i.id)
			        i.id::text, i.tenant_id::text, i.kind, i.name, i.owner_id::text,
			        i.issuer_id::text, i.status, i.not_before, i.not_after, i.attributes, i.created_at,
			        c.id::text, c.tenant_id::text, c.owner_id::text, c.subject, c.sans, c.issuer, c.serial,
			        c.fingerprint, c.key_algorithm, c.not_before, c.not_after, c.deployment_location, c.source,
			        c.certificate_der, c.issuance_idempotency_key, c.created_at, c.validity_anchor,
			        c.status, c.replaces_id::text, c.revoked_at, c.revocation_reason, c.renewed_at, c.alerted_at
			   FROM identities i
			   JOIN certificates c
			     ON c.tenant_id = i.tenant_id
			    AND c.owner_id = i.owner_id
			    AND i.name = ANY(c.sans)
			  WHERE i.tenant_id = $1
			    AND i.kind = 'x509_certificate'
			    AND i.status IN ('deployed', 'renewal_failed')
			    AND NOT EXISTS (SELECT 1 FROM identities replacement
			      WHERE replacement.tenant_id = i.tenant_id
			        AND replacement.attributes->>'endpoint_replaces_identity_id' = i.id::text
			        AND replacement.status IN ('issued', 'deployed', 'renewing', 'renewal_failed'))
			    AND c.source = 'issued'
			    AND (c.status = 'active' OR (c.status = 'superseded' AND EXISTS (
			      SELECT 1 FROM connector_delivery_receipts restored
			       WHERE restored.tenant_id = $1 AND restored.tenant_id = i.tenant_id
			         AND restored.identity_id = i.id AND restored.fingerprint = c.fingerprint
			         AND restored.destination = 'connector.rollback' AND restored.status = 'rolled_back'
			    )))
			    AND c.not_after IS NOT NULL
			    AND (
			         c.not_after < $2
			         OR (
			              c.not_before IS NOT NULL
			              AND c.not_after - ((c.not_after - c.not_before) / 3.0) <= $3
			            )
			        )
			  ORDER BY i.id, c.not_after, c.created_at`,
			tenantID, fixedCutoff, ariNow)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				it    Identity
				kind  string
				attrs []byte
				cert  Certificate
			)
			if err := rows.Scan(&it.ID, &it.TenantID, &kind, &it.Name, &it.OwnerID, &it.IssuerID,
				&it.Status, &it.NotBefore, &it.NotAfter, &attrs, &it.CreatedAt,
				&cert.ID, &cert.TenantID, &cert.OwnerID, &cert.Subject, &cert.SANs, &cert.Issuer, &cert.Serial,
				&cert.Fingerprint, &cert.KeyAlgorithm, &cert.NotBefore, &cert.NotAfter, &cert.DeploymentLocation, &cert.Source,
				&cert.CertificateDER, &cert.IssuanceIdempotencyKey, &cert.CreatedAt, &cert.ValidityAnchor,
				&cert.Status, &cert.ReplacesID, &cert.RevokedAt, &cert.RevocationReason, &cert.RenewedAt, &cert.AlertedAt); err != nil {
				return err
			}
			it.Kind = IdentityKind(kind)
			it.Attributes = attrs
			out = append(out, RenewalIdentityCandidate{Identity: it, Certificate: cert})
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithRenewableIdentities returns tenant ids that currently have at least
// one deployed X.509 identity eligible for scheduled renewal. It is a system
// enumerator for the leader-only scheduler; each tenant's actual identities are
// then loaded through ListRenewableIdentities under that tenant's RLS context.
func (s *Store) TenantsWithRenewableIdentities(ctx context.Context, cutoff time.Time) ([]string, error) {
	return s.TenantsWithRenewalIdentityCandidates(ctx, cutoff, time.Time{})
}

// TenantsWithRenewalIdentityCandidates returns tenant ids that currently have at
// least one deployed X.509 identity whose active or proved-restored issued certificate should be
// evaluated by the scheduler. It is a system enumerator only: each tenant's rows
// are loaded through ListRenewalIdentityCandidates under tenant-scoped RLS.
func (s *Store) TenantsWithRenewalIdentityCandidates(ctx context.Context, fixedCutoff, ariNow time.Time) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader scheduler enumerates which tenants have renewal work, then re-enters tenant-scoped RLS for the rows themselves.
		`SELECT DISTINCT i.tenant_id::text
		   FROM identities i
		   JOIN certificates c
		     ON c.tenant_id = i.tenant_id
		    AND c.owner_id = i.owner_id
		    AND i.name = ANY(c.sans)
		  WHERE i.kind = 'x509_certificate'
		    AND i.status IN ('deployed', 'renewal_failed')
		    AND c.source = 'issued'
		    AND (c.status = 'active' OR (c.status = 'superseded' AND EXISTS (
		      SELECT 1 FROM connector_delivery_receipts restored
		       WHERE restored.tenant_id = i.tenant_id
		         AND restored.identity_id = i.id AND restored.fingerprint = c.fingerprint
		         AND restored.destination = 'connector.rollback' AND restored.status = 'rolled_back'
		    )))
		    AND c.not_after IS NOT NULL
		    AND (
		         c.not_after < $1
		         OR (
		              c.not_before IS NOT NULL
		              AND c.not_after - ((c.not_after - c.not_before) / 3.0) <= $2
		            )
		        )
		  ORDER BY 1`, fixedCutoff, ariNow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

// DeploymentTriState is the estate roll-up of issued / delivered / verified
// (epic D3).
//
// Three counts rather than one, because they are three different claims about
// the same certificate and only the third one is what an operator wanted.
// Counting deliveries and calling it health is counting INTENTIONS — the
// pipeline's own account of what it did — which is precisely the blindness the
// verification engine exists to remove. A surface that kept counting deliveries
// after verification shipped would waste it.
type DeploymentTriState struct {
	// Delivered is targets whose most recent deploy receipt says a connector
	// applied the credential.
	Delivered int
	// Verified is targets whose most recent verification receipt says a
	// handshake found the endpoint serving it.
	Verified int
	// VerifyFailed is targets where the credential was applied and the endpoint
	// is serving something else.
	VerifyFailed int
	// Unverified is delivered targets with NO verification receipt at all.
	//
	// The honest middle. It is not a failure and it is emphatically not a pass:
	// nobody has looked. Folding it into either would be the overclaim this
	// whole epic exists to remove — and on a fresh install every target is
	// here, which is the correct starting picture.
	Unverified int
}

// SummarizeDeploymentTriState rolls delivery receipts up per target.
func (s *Store) SummarizeDeploymentTriState(ctx context.Context, tenantID string) (DeploymentTriState, error) {
	var out DeploymentTriState
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Per (connector, target), the LATEST receipt of each kind. A target
		// deployed ten times and verified once is verified; a target verified
		// last month and diverged today is failed. Both fall out of taking the
		// most recent of each rather than counting rows.
		return tx.QueryRow(ctx,
			`WITH latest AS (
			   SELECT DISTINCT ON (connector, target)
			          connector, target, status
			     FROM connector_delivery_receipts
			    WHERE tenant_id = $1
			      AND destination = 'connector.deploy'
			      AND status IN ('delivered', 'verified', 'verify_failed')
			    ORDER BY connector, target, updated_at DESC, id DESC
			 ),
			 verified_targets AS (
			   SELECT DISTINCT ON (connector, target)
			          connector, target, status
			     FROM connector_delivery_receipts
			    WHERE tenant_id = $1
			      AND destination = 'connector.deploy'
			      AND status IN ('verified', 'verify_failed')
			    ORDER BY connector, target, updated_at DESC, id DESC
			 )
			 SELECT
			   (SELECT count(*) FROM latest),
			   (SELECT count(*) FROM verified_targets WHERE status = 'verified'),
			   (SELECT count(*) FROM verified_targets WHERE status = 'verify_failed'),
			   (SELECT count(*) FROM latest l
			      WHERE NOT EXISTS (SELECT 1 FROM verified_targets v
			                         WHERE v.connector = l.connector AND v.target = l.target))`,
			tenantID).Scan(&out.Delivered, &out.Verified, &out.VerifyFailed, &out.Unverified)
	})
	return out, err
}

// FleetVerificationOutcome is what verification says about one fleet run's
// replacement identities (epic D6).
type FleetVerificationOutcome struct {
	// Verified is replacements whose latest verification receipt says a
	// handshake found the endpoint serving them.
	Verified int
	// Failed is replacements whose endpoint is serving something else, or
	// could not be reached.
	Failed int
	// Unverified is replacements with no verification receipt at all. It is
	// what keeps a gate at not_evaluated rather than letting silence read as
	// success.
	Unverified int
}

// SummarizeFleetVerification reports the verification outcome for a set of
// identities. A connector receipt counts only when its deployment outbox row
// has a matching agent_job_receipts row whose signature was accepted. A plain
// delivery projection, an unsigned report, or a rejected signature is absence,
// never authority to release another fleet batch.
//
// This is what turns a fleet health gate from a label into a verdict. Until
// D2/D3 nothing re-read an endpoint, so every gate trstctl filled in itself was
// not_evaluated — correctly, because a verdict nobody computed is not a pass.
// Now there are receipts to compute one from.
//
// The rule the caller depends on: ANY failure makes the gate fail, and any
// absence keeps it unevaluated. A run cannot show all-green while one of its
// replacements is not being served, and it cannot show green for replacements
// nobody looked at.
func (s *Store) SummarizeFleetVerification(ctx context.Context, tenantID string, identityIDs []string) (FleetVerificationOutcome, error) {
	var out FleetVerificationOutcome
	if len(identityIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`WITH latest AS (
			   SELECT DISTINCT ON (c.identity_id)
			          c.identity_id, c.status
			     FROM connector_delivery_receipts c
			     JOIN outbox o
			       ON o.tenant_id = c.tenant_id
			      AND c.idempotency_key = o.idempotency_key || ':verified'
			     JOIN agent_job_receipts a
			       ON a.tenant_id = o.tenant_id AND a.job_id = o.id
			      AND a.state = 'verified'
			    WHERE c.tenant_id = $1
			      AND c.identity_id = ANY($2::uuid[])
			      AND c.status IN ('verified', 'verify_failed')
			    ORDER BY c.identity_id, c.updated_at DESC, c.id DESC
			 )
			 SELECT
			   (SELECT count(*) FROM latest WHERE status = 'verified'),
			   (SELECT count(*) FROM latest WHERE status = 'verify_failed'),
			   (SELECT count(*) FROM unnest($2::uuid[]) AS wanted(id)
			      WHERE NOT EXISTS (SELECT 1 FROM latest l WHERE l.identity_id = wanted.id))`,
			tenantID, identityIDs).Scan(&out.Verified, &out.Failed, &out.Unverified)
	})
	return out, err
}

// RenewalSLO is the renewal success rate and its error budget (epic D6).
//
// An SLO is only useful if it is measured over a window an operator chose and
// against a target they set. Both are inputs here rather than constants: a
// 99.9% target over 30 days and a 99% target over 7 days are different
// promises, and a surface that picked for them would be reporting compliance
// with a standard nobody agreed to.
type RenewalSLO struct {
	// WindowDays is the measurement window.
	WindowDays int
	// TargetPercent is the success rate the operator committed to.
	TargetPercent float64
	// Total, Succeeded and Failed are renewal runs that reached a terminal
	// state inside the window. Runs still in flight are excluded: counting an
	// unfinished renewal as a failure would burn budget for work that may yet
	// succeed, and counting it as a success would be worse.
	Total     int
	Succeeded int
	Failed    int
	// ObservedPercent is the achieved success rate, or 100 when nothing ran.
	//
	// A window with no renewals is not a breach. It is an estate where nothing
	// was due, and reporting 0% for it would page someone about the absence of
	// work — the single fastest way to teach a team to ignore an SLO.
	ObservedPercent float64
	// BudgetRemainingPercent is how much of the error budget is left, 0-100.
	// Negative burn is clamped: an SLO that reports -340% consumed is not more
	// actionable than one reporting 0 left, and the raw counts are right there.
	BudgetRemainingPercent float64
}

// Breached reports whether the observed rate is below target.
func (s RenewalSLO) Breached() bool { return s.Total > 0 && s.ObservedPercent < s.TargetPercent }

// SummarizeRenewalSLO computes the renewal success SLO over a window.
//
// Terminal runs only. A renewal that is still executing is neither a success
// nor a failure yet, and forcing it into either would make the number move for
// reasons unrelated to reliability.
func (s *Store) SummarizeRenewalSLO(ctx context.Context, tenantID string, windowDays int, targetPercent float64) (RenewalSLO, error) {
	if windowDays <= 0 {
		windowDays = 30
	}
	if targetPercent <= 0 {
		targetPercent = 99
	}
	out := RenewalSLO{WindowDays: windowDays, TargetPercent: targetPercent, ObservedPercent: 100, BudgetRemainingPercent: 100}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The tenant scope is applied in the CTE, before any aggregate. Written
		// this way on purpose: with FILTER (WHERE ...) clauses in the select
		// list, the tenant predicate stops being the first WHERE a reader — or
		// the AN-1 linter — encounters, and a scope you have to hunt for is one
		// a later edit can drop without anyone noticing.
		return tx.QueryRow(ctx,
			`WITH scoped AS (
			   SELECT status
			     FROM lifecycle_rotation_runs
			    WHERE tenant_id = $1
			      AND updated_at >= now() - make_interval(days => $2)
			 )
			 SELECT
			   count(*) FILTER (WHERE status IN ('completed', 'failed')),
			   count(*) FILTER (WHERE status = 'completed'),
			   count(*) FILTER (WHERE status = 'failed')
			 FROM scoped`,
			tenantID, windowDays).Scan(&out.Total, &out.Succeeded, &out.Failed)
	})
	if err != nil {
		return RenewalSLO{}, err
	}
	if out.Total == 0 {
		// Nothing was due. Not a breach — see the field comment.
		return out, nil
	}
	out.ObservedPercent = float64(out.Succeeded) * 100 / float64(out.Total)

	// The error budget is the share of allowed failures that remains. A 99%
	// target over 100 runs allows one failure; two failures is 0% remaining,
	// not -100%.
	allowedFailureRate := 100 - targetPercent
	if allowedFailureRate <= 0 {
		// A 100% target has no budget at all: any failure is a breach, and
		// saying "0% remaining" the moment one occurs is the honest rendering.
		if out.Failed > 0 {
			out.BudgetRemainingPercent = 0
		}
		return out, nil
	}
	observedFailureRate := float64(out.Failed) * 100 / float64(out.Total)
	remaining := (1 - observedFailureRate/allowedFailureRate) * 100
	if remaining < 0 {
		remaining = 0
	}
	if remaining > 100 {
		remaining = 100
	}
	out.BudgetRemainingPercent = remaining
	return out, nil
}

// ConnectorRollbackProjectionNeedsRebuild detects receipts written before their
// envelope sequence was retained. A global checkpoint cannot order those rows
// against an existing durable consumer that is still behind that checkpoint.
func (s *Store) ConnectorRollbackProjectionNeedsRebuild(ctx context.Context) (bool, error) {
	var missing bool
	err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — boot recovery must detect legacy rollback receipts across all tenants before serving; returns only a boolean and no tenant data (AN-1 exemption).
		`SELECT EXISTS(SELECT 1 FROM connector_delivery_receipts WHERE destination='connector.rollback' AND coalesce(latest_event_sequence,0)=0)`).Scan(&missing)
	return missing, err
}
