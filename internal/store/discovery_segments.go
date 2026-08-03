// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
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
	ID     string
	Name   string
	Ranges []string
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
	if seg.StalenessHours <= 0 {
		seg.StalenessHours = 168
	}
	ranges := seg.Ranges
	if ranges == nil {
		ranges = []string{}
	}
	var out DiscoverySegment
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO discovery_segments
			     (tenant_id, id, name, ranges, staleness_hours, excluded, exclusion_reason)
			 VALUES ($1, COALESCE(NULLIF($2,'')::uuid, gen_random_uuid()), $3, $4::text[], $5, $6, $7)
			 ON CONFLICT (tenant_id, name) DO UPDATE
			    SET ranges = EXCLUDED.ranges,
			        staleness_hours = EXCLUDED.staleness_hours,
			        excluded = EXCLUDED.excluded,
			        exclusion_reason = EXCLUDED.exclusion_reason
			 RETURNING id::text, name, ranges, staleness_hours, excluded, exclusion_reason,
			           last_swept_at, last_swept_by, last_found_count, created_at`,
			tenantID, seg.ID, seg.Name, ranges, seg.StalenessHours, seg.Excluded, seg.ExclusionReason).
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
		_, err := tx.Exec(ctx,
			`UPDATE discovery_segments
			    SET last_swept_at = $3, last_swept_by = $4, last_found_count = $5
			  WHERE tenant_id = $1 AND name = $2`,
			tenantID, name, at.UTC(), sweptBy, found)
		return err
	})
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
