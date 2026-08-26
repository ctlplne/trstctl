// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Declared segments and their sweep freshness (epic C3).
//
// The point of declaring a segment is that it makes "never swept" reportable.
// An inventory assembled only from what discovery found can describe what it
// found; it cannot describe what nobody looked at, and that is the number an
// auditor asks for. Measuring reality against an operator's own declaration is
// the only way to produce it.

// DiscoverySegment is one declared network segment.
type DiscoverySegment struct {
	ID                      string
	Name                    string
	Ranges                  []string
	ProjectionEventID       string
	ProjectionEventSequence uint64
	// StalenessHours is the operator's own SLO for this segment. Past it, a
	// sweep result stops being evidence. Per segment because a DMZ and a lab do
	// not deserve the same answer.
	StalenessHours int
	// Excluded marks a DECLARED blind spot — an operator has said on the record
	// that this network is out of scope. Legitimate, and completely different
	// from a segment nobody has reached yet.
	Excluded        bool
	ExclusionReason string
	LastSweptAt     *time.Time
	LastSweptBy     string
	LastFoundCount  int
	CreatedAt       time.Time
}

// UpsertDiscoverySegment declares a segment, or updates its declaration.
//
// It deliberately does NOT touch the observation columns. A re-declaration is
// an operator editing a boundary or an SLO; treating that as an observation
// would let a segment look freshly swept because somebody renamed it.
func (s *Store) UpsertDiscoverySegment(ctx context.Context, tenantID string, seg DiscoverySegment) (DiscoverySegment, error) {
	var out DiscoverySegment
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.ApplyDiscoverySegmentUpsertedTx(ctx, tx, tenantID, seg)
		return err
	})
	return out, err
}

// ApplyDiscoverySegmentUpsertedTx projects a declared segment from its
// immutable event. Observation columns are deliberately preserved on update.
func (s *Store) ApplyDiscoverySegmentUpsertedTx(ctx context.Context, tx pgx.Tx, tenantID string, seg DiscoverySegment) (DiscoverySegment, error) {
	if seg.StalenessHours <= 0 {
		seg.StalenessHours = 168
	}
	ranges := seg.Ranges
	if ranges == nil {
		ranges = []string{}
	}
	createdAt := seg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	eventSequence := int64(seg.ProjectionEventSequence) // #nosec G115 -- JetStream event sequences are stored in PostgreSQL bigint throughout the projection spine (CWE-190)
	manualWrite := seg.ProjectionEventID == "" || seg.ProjectionEventSequence == 0
	var out DiscoverySegment
	var appliedSequence int64
	if manualWrite {
		// Direct store callers are setup/compatibility code, not the production
		// command path. Preserve their historical tenant+name upsert contract, but
		// never let an unversioned write overwrite a row already owned by an
		// immutable event.
		err := tx.QueryRow(ctx,
			`INSERT INTO discovery_segments
			     (tenant_id, id, name, ranges, staleness_hours, excluded, exclusion_reason, created_at)
			 VALUES ($1, COALESCE(NULLIF($2,'')::uuid, gen_random_uuid()), $3, $4::text[], $5, $6, $7, $8)
			 ON CONFLICT (tenant_id, name) DO UPDATE
			    SET ranges = EXCLUDED.ranges,
			        staleness_hours = EXCLUDED.staleness_hours,
			        excluded = EXCLUDED.excluded,
			        exclusion_reason = EXCLUDED.exclusion_reason
			  WHERE discovery_segments.projection_event_id IS NULL
			    AND discovery_segments.projection_event_sequence = 0
			 RETURNING id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
			           last_swept_at, last_swept_by, last_found_count, created_at,
			           COALESCE(projection_event_id, ''), projection_event_sequence`,
			tenantID, seg.ID, seg.Name, ranges, seg.StalenessHours, seg.Excluded, seg.ExclusionReason, createdAt).
			Scan(&out.ID, &out.Name, &out.Ranges, &out.StalenessHours, &out.Excluded,
				&out.ExclusionReason, &out.LastSweptAt, &out.LastSweptBy, &out.LastFoundCount, &out.CreatedAt,
				&out.ProjectionEventID, &appliedSequence)
		if err != nil {
			return DiscoverySegment{}, discoveryDeclarationWriteError("segment", err)
		}
		out.ProjectionEventSequence = uint64(appliedSequence) // #nosec G115 -- the migration constrains this PostgreSQL bigint to non-negative values (CWE-190)
		return out, nil
	}

	// Migration 0199 adds ordering metadata to rows created before discovery
	// declarations were fully event-backed. Bind such a row to its first event
	// exactly once, including the event's deterministic ID and creation time.
	// After this adoption every replay goes through the strict ordered path.
	err := tx.QueryRow(ctx,
		`UPDATE discovery_segments
		    SET id = $2::uuid,
		        ranges = $4::text[],
		        staleness_hours = $5,
		        excluded = $6,
		        exclusion_reason = $7,
		        created_at = $8,
		        projection_event_id = $9,
		        projection_event_sequence = $10
		  WHERE tenant_id = $1
		    AND name = $3
		    AND projection_event_id IS NULL
		    AND projection_event_sequence = 0
		 RETURNING id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
		           last_swept_at, last_swept_by, last_found_count, created_at,
		           COALESCE(projection_event_id, ''), projection_event_sequence`,
		tenantID, seg.ID, seg.Name, ranges, seg.StalenessHours, seg.Excluded, seg.ExclusionReason, createdAt,
		seg.ProjectionEventID, eventSequence).
		Scan(&out.ID, &out.Name, &out.Ranges, &out.StalenessHours, &out.Excluded,
			&out.ExclusionReason, &out.LastSweptAt, &out.LastSweptBy, &out.LastFoundCount, &out.CreatedAt,
			&out.ProjectionEventID, &appliedSequence)
	if err == nil {
		out.ProjectionEventSequence = uint64(appliedSequence) // #nosec G115 -- the migration constrains this PostgreSQL bigint to non-negative values (CWE-190)
		if err := validateDiscoverySegmentProjectionResult(seg, out); err != nil {
			return DiscoverySegment{}, err
		}
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return DiscoverySegment{}, discoveryDeclarationWriteError("segment", err)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO discovery_segments
			     (tenant_id, id, name, ranges, staleness_hours, excluded, exclusion_reason, created_at,
			      projection_event_id, projection_event_sequence)
			 VALUES ($1, COALESCE(NULLIF($2,'')::uuid, gen_random_uuid()), $3, $4::text[], $5, $6, $7, $8,
			         NULLIF($9, ''), $10)
			 ON CONFLICT ON CONSTRAINT discovery_segments_pkey DO UPDATE
			    SET ranges = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.ranges ELSE discovery_segments.ranges END,
			        staleness_hours = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.staleness_hours ELSE discovery_segments.staleness_hours END,
			        excluded = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.excluded ELSE discovery_segments.excluded END,
			        exclusion_reason = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.exclusion_reason ELSE discovery_segments.exclusion_reason END,
			        projection_event_id = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.projection_event_id ELSE discovery_segments.projection_event_id END,
			        projection_event_sequence = CASE WHEN (
			            EXCLUDED.projection_event_sequence > discovery_segments.projection_event_sequence
			            AND discovery_segments.projection_event_id IS DISTINCT FROM EXCLUDED.projection_event_id
			            AND discovery_segments.name = EXCLUDED.name
			        ) THEN EXCLUDED.projection_event_sequence ELSE discovery_segments.projection_event_sequence END
			 RETURNING id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
			           last_swept_at, last_swept_by, last_found_count, created_at,
			           COALESCE(projection_event_id, ''), projection_event_sequence`,
		tenantID, seg.ID, seg.Name, ranges, seg.StalenessHours, seg.Excluded, seg.ExclusionReason, createdAt,
		seg.ProjectionEventID, eventSequence).
		Scan(&out.ID, &out.Name, &out.Ranges, &out.StalenessHours, &out.Excluded,
			&out.ExclusionReason, &out.LastSweptAt, &out.LastSweptBy, &out.LastFoundCount, &out.CreatedAt,
			&out.ProjectionEventID, &appliedSequence)
	if err != nil {
		return DiscoverySegment{}, discoveryDeclarationWriteError("segment", err)
	}
	out.ProjectionEventSequence = uint64(appliedSequence) // #nosec G115 -- the migration constrains this PostgreSQL bigint to non-negative values (CWE-190)
	if err := validateDiscoverySegmentProjectionResult(seg, out); err != nil {
		return DiscoverySegment{}, err
	}
	return out, nil
}

func validateDiscoverySegmentProjectionResult(expected, applied DiscoverySegment) error {
	switch {
	case applied.ProjectionEventSequence < expected.ProjectionEventSequence:
		return fmt.Errorf("%w: segment %s did not advance to event %s sequence %d",
			ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID, expected.ProjectionEventSequence)
	case applied.ProjectionEventSequence > expected.ProjectionEventSequence:
		if applied.ProjectionEventID == expected.ProjectionEventID {
			return fmt.Errorf("%w: segment %s reuses event %s at sequences %d and %d",
				ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID,
				expected.ProjectionEventSequence, applied.ProjectionEventSequence)
		}
		return nil
	default:
		if applied.ProjectionEventID != expected.ProjectionEventID ||
			applied.ID != expected.ID || applied.Name != expected.Name ||
			!slices.Equal(applied.Ranges, expected.Ranges) ||
			applied.StalenessHours != expected.StalenessHours ||
			applied.Excluded != expected.Excluded ||
			applied.ExclusionReason != expected.ExclusionReason {
			return fmt.Errorf("%w: segment %s event %s sequence %d differs from the accepted declaration",
				ErrDiscoveryDeclarationEventConflict, expected.ID, expected.ProjectionEventID,
				expected.ProjectionEventSequence)
		}
		return nil
	}
}

// GetDiscoverySegmentByName resolves the immutable queue-time segment binding
// inside the tenant's RLS context.
func (s *Store) GetDiscoverySegmentByName(ctx context.Context, tenantID, name string) (DiscoverySegment, error) {
	var out DiscoverySegment
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
			        last_swept_at, last_swept_by, last_found_count, created_at
			   FROM discovery_segments
			  WHERE tenant_id = $1 AND name = $2`, tenantID, name).
			Scan(&out.ID, &out.Name, &out.Ranges, &out.StalenessHours, &out.Excluded,
				&out.ExclusionReason, &out.LastSweptAt, &out.LastSweptBy, &out.LastFoundCount, &out.CreatedAt)
	})
	return out, err
}

// RecordSegmentSweep records that a sweep observed a segment.
//
// Written from a completed sweep rather than from the request that started one:
// a sweep that was requested and never ran must leave the segment reading as
// stale, because it is.
func (s *Store) RecordSegmentSweep(ctx context.Context, tenantID, name, sweptBy string, found int, at time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.ApplyDiscoverySegmentSweepTx(ctx, tx, tenantID, name, sweptBy, found, at)
	})
}

// ApplyDiscoverySegmentSweepTx projects relay execution provenance from the
// same discovery.run.completed event that closes the run.
func (s *Store) ApplyDiscoverySegmentSweepTx(ctx context.Context, tx pgx.Tx, tenantID, name, sweptBy string, found int, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE discovery_segments
		    SET last_swept_at = $3, last_swept_by = $4, last_found_count = $5
		  WHERE tenant_id = $1 AND name = $2`,
		tenantID, name, at.UTC(), sweptBy, found)
	return err
}

// ListDiscoverySegments returns a tenant's declared segments, least recently
// swept first — which is the order an operator wants, because the top of that
// list is the answer to "what am I blind to".
func (s *Store) ListDiscoverySegments(ctx context.Context, tenantID string) ([]DiscoverySegment, error) {
	var out []DiscoverySegment
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
			        last_swept_at, last_swept_by, last_found_count, created_at
			   FROM discovery_segments
			  WHERE tenant_id = $1
			  ORDER BY last_swept_at NULLS FIRST, name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var seg DiscoverySegment
			if err := rows.Scan(&seg.ID, &seg.Name, &seg.Ranges, &seg.StalenessHours, &seg.Excluded,
				&seg.ExclusionReason, &seg.LastSweptAt, &seg.LastSweptBy, &seg.LastFoundCount,
				&seg.CreatedAt); err != nil {
				return err
			}
			out = append(out, seg)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteDiscoverySegment removes a declaration.
func (s *Store) DeleteDiscoverySegment(ctx context.Context, tenantID, id string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM discovery_segments WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		return err
	})
}

// CertificateProvenanceCounts summarizes how much of the inventory has an
// observation behind it.
//
// This is the number that stops a certificate count being read as an inventory.
// A row trstctl issued and nothing has since re-observed is not evidence the
// certificate is still deployed — it is evidence it was once issued.
type CertificateProvenanceCounts struct {
	Total int
	// Observed have a recorded last-seen from some source.
	Observed int
	// Stale were observed, but longer ago than the window asked for.
	Stale int
	// NeverObserved have no observation at all. Not a defect — a certificate
	// this control plane issued and nothing has scanned is legitimately here —
	// but it must not be counted as verified inventory.
	NeverObserved int
}

// CertificateProvenance counts the tenant's inventory by observation freshness.
func (s *Store) CertificateProvenance(ctx context.Context, tenantID string, staleBefore time.Time) (CertificateProvenanceCounts, error) {
	var out CertificateProvenanceCounts
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*)::int,
			        count(*) FILTER (WHERE last_seen_at IS NOT NULL)::int,
			        count(*) FILTER (WHERE last_seen_at IS NOT NULL AND last_seen_at < $2)::int,
			        count(*) FILTER (WHERE last_seen_at IS NULL)::int
			   FROM certificates WHERE tenant_id = $1`,
			tenantID, staleBefore.UTC()).
			Scan(&out.Total, &out.Observed, &out.Stale, &out.NeverObserved)
	})
	return out, err
}
