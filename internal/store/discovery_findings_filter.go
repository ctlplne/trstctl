// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Filtered discovery findings (A105). The Posture dashboards for CT-log and
// drift findings read one source kind's findings a page at a time and count
// them on the server, so neither a first-page sample nor another kind's
// findings decide what an operator sees.

// DiscoveryFindingFilter narrows a findings read. Empty fields do not filter.
// SourceKind matches the kind of the source a finding was recorded under;
// TriageStatus "unmanaged" also matches a finding never triaged.
type DiscoveryFindingFilter struct {
	RunID        string
	SourceKind   string
	Kind         string
	TriageStatus string
}

// MaxDiscoveryFindingTallyGroups bounds one count: the dashboards count one
// source kind, whose findings fall in a handful of groups.
const MaxDiscoveryFindingTallyGroups = 1000

// MaxDiscoverySourcesOfKind bounds one source-kind read.
const MaxDiscoverySourcesOfKind = 1000

// ErrDiscoveryFindingTallyTooWide reports a count over more groups than one
// read returns; narrow the filter.
var ErrDiscoveryFindingTallyTooWide = errors.New("store: discovery finding count spans too many groups; narrow the filter")

// where appends the filter's predicates to a query over discovery_findings f.
func (f DiscoveryFindingFilter) where(args []any) (string, []any) {
	var b strings.Builder
	if f.RunID != "" {
		args = append(args, f.RunID)
		fmt.Fprintf(&b, " AND f.run_id = $%d", len(args))
	}
	if f.Kind != "" {
		args = append(args, f.Kind)
		fmt.Fprintf(&b, " AND f.kind = $%d", len(args))
	}
	if f.TriageStatus != "" {
		args = append(args, f.TriageStatus)
		if f.TriageStatus == "unmanaged" {
			fmt.Fprintf(&b, " AND f.triage_status IN ('', $%d)", len(args))
		} else {
			fmt.Fprintf(&b, " AND f.triage_status = $%d", len(args))
		}
	}
	if f.SourceKind != "" {
		args = append(args, f.SourceKind)
		fmt.Fprintf(&b, " AND f.source_id IN (SELECT s.id FROM discovery_sources s WHERE s.tenant_id = f.tenant_id AND s.kind = $%d)", len(args))
	}
	return b.String(), args
}

// ListDiscoveryFindingsFiltered pages the findings a filter matches by id
// keyset.
func (s *Store) ListDiscoveryFindingsFiltered(ctx context.Context, tenantID string, filter DiscoveryFindingFilter, afterID string, limit int) ([]DiscoveryFinding, error) {
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		where, args := filter.where([]any{tenantID, afterID, limit})
		rows, err := tx.Query(ctx, `SELECT f.id::text, f.tenant_id::text, f.run_id::text, f.source_id::text, f.kind, f.ref,
		              f.provenance, f.fingerprint, f.risk_score, f.metadata, f.discovered_at,
		              f.triage_status, f.managed_identity_id::text, f.triage_actor, f.triage_reason, f.triaged_at,
		              f.first_seen_at, f.last_seen_at, f.seen_count
		         FROM discovery_findings f
		        WHERE f.tenant_id = $1 AND f.id > $2`+where+`
		        ORDER BY f.id LIMIT $3`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f DiscoveryFinding
			if err := scanDiscoveryFinding(rows, &f); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// DiscoveryFindingTally is one group of a filtered count: the triage status
// (never-triaged folded into unmanaged), the finding kind, and the metadata
// type and class a drift finding carries ("" when absent).
type DiscoveryFindingTally struct {
	TriageStatus string
	Kind         string
	Type         string
	Class        string
	Count        int
}

// TallyDiscoveryFindings counts every finding a filter matches, grouped, so a
// dashboard's totals come from the server rather than from a page.
func (s *Store) TallyDiscoveryFindings(ctx context.Context, tenantID string, filter DiscoveryFindingFilter) ([]DiscoveryFindingTally, error) {
	var out []DiscoveryFindingTally
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		where, args := filter.where([]any{tenantID, MaxDiscoveryFindingTallyGroups + 1})
		rows, err := tx.Query(ctx, `SELECT CASE WHEN f.triage_status = '' THEN 'unmanaged' ELSE f.triage_status END,
		              f.kind, COALESCE(f.metadata->>'type', ''), COALESCE(f.metadata->>'class', ''), count(*)
		         FROM discovery_findings f
		        WHERE f.tenant_id = $1`+where+`
		        GROUP BY 1, 2, 3, 4
		        ORDER BY 1, 2, 3, 4 LIMIT $2`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t DiscoveryFindingTally
			if err := rows.Scan(&t.TriageStatus, &t.Kind, &t.Type, &t.Class, &t.Count); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err == nil && len(out) > MaxDiscoveryFindingTallyGroups {
		return nil, ErrDiscoveryFindingTallyTooWide
	}
	return out, err
}

// ListDiscoverySourcesOfKind reads a tenant's sources of one kind, by id.
func (s *Store) ListDiscoverySourcesOfKind(ctx context.Context, tenantID, kind string) ([]DiscoverySource, error) {
	var out []DiscoverySource
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, name, config, created_at, updated_at
			   FROM discovery_sources
			  WHERE tenant_id = $1 AND kind = $2
			  ORDER BY id LIMIT $3`, tenantID, kind, MaxDiscoverySourcesOfKind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var src DiscoverySource
			if err := scanDiscoverySource(rows, &src); err != nil {
				return err
			}
			out = append(out, src)
		}
		return rows.Err()
	})
	return out, err
}
