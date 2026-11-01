// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Credential usage (M1): when, and from where, each credential was last used,
// from trstctl's own activity. Kinds: an API token (its id; sources are client
// networks) and a machine login method (its name; sources are the workloads it
// attested). Projections of credential.used and secrets.session.started.
const (
	CredentialUsageAPIToken    = "api_token"
	CredentialUsageMachineAuth = "machine_auth"

	CredentialUsageSourceNetwork     = "network"
	CredentialUsageSourceAttestation = "attestation"
)

// CredentialUse is one recorded use, as the projection folds it.
type CredentialUse struct {
	TenantID     string
	Kind         string
	CredentialID string
	Principal    string
	SourceKind   string
	Source       string
	UsedAt       time.Time
}

// CredentialUsage is a credential's first and last recorded use.
type CredentialUsage struct {
	Kind         string
	CredentialID string
	Principal    string
	FirstUsedAt  time.Time
	LastUsedAt   time.Time
	LastSource   string
}

// CredentialUsageSource is one place a credential was used from. DaysSeen
// counts the distinct UTC days on which it was used from there.
type CredentialUsageSource struct {
	CredentialID string
	SourceKind   string
	Source       string
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	DaysSeen     int
}

// CredentialUsageGap is a window in which uses could not be recorded.
type CredentialUsageGap struct {
	ID      string
	From    time.Time
	To      time.Time
	Dropped int64
}

func usageSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return 0, fmt.Errorf("store: credential usage requires a positive int64 event sequence")
	}
	return int64(sequence), nil // #nosec G115 -- bounded to int64 above (CWE-190)
}

// ApplyCredentialUseTx folds one use into the credential's row and its
// source's row. An event already folded (same or older sequence) changes
// nothing, so a replay is exact.
func (s *Store) ApplyCredentialUseTx(ctx context.Context, tx pgx.Tx, u CredentialUse, sequence uint64) error {
	if u.TenantID == "" || u.Kind == "" || u.CredentialID == "" || u.SourceKind == "" || u.Source == "" || u.UsedAt.IsZero() {
		return fmt.Errorf("store: credential use is incomplete")
	}
	seq, err := usageSequence(sequence)
	if err != nil {
		return err
	}
	usedAt := u.UsedAt.UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO credential_usage (tenant_id, kind, credential_id, principal, first_used_at, last_used_at, last_source, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
		ON CONFLICT (tenant_id, kind, credential_id) DO UPDATE SET
		    principal = CASE WHEN EXCLUDED.last_used_at >= credential_usage.last_used_at THEN EXCLUDED.principal ELSE credential_usage.principal END,
		    last_source = CASE WHEN EXCLUDED.last_used_at >= credential_usage.last_used_at THEN EXCLUDED.last_source ELSE credential_usage.last_source END,
		    first_used_at = least(credential_usage.first_used_at, EXCLUDED.first_used_at),
		    last_used_at = greatest(credential_usage.last_used_at, EXCLUDED.last_used_at),
		    event_sequence = EXCLUDED.event_sequence
		 WHERE credential_usage.event_sequence < EXCLUDED.event_sequence`,
		u.TenantID, u.Kind, u.CredentialID, u.Principal, usedAt, u.Source, seq); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO credential_usage_sources
		    (tenant_id, kind, credential_id, source_kind, source, first_seen_at, last_seen_at, days_seen, last_day, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $6, 1, ($6 AT TIME ZONE 'UTC')::date, $7)
		ON CONFLICT (tenant_id, kind, credential_id, source_kind, source) DO UPDATE SET
		    first_seen_at = least(credential_usage_sources.first_seen_at, EXCLUDED.first_seen_at),
		    last_seen_at = greatest(credential_usage_sources.last_seen_at, EXCLUDED.last_seen_at),
		    days_seen = credential_usage_sources.days_seen
		        + CASE WHEN EXCLUDED.last_day > credential_usage_sources.last_day THEN 1 ELSE 0 END,
		    last_day = greatest(credential_usage_sources.last_day, EXCLUDED.last_day),
		    event_sequence = EXCLUDED.event_sequence
		 WHERE credential_usage_sources.event_sequence < EXCLUDED.event_sequence`,
		u.TenantID, u.Kind, u.CredentialID, u.SourceKind, u.Source, usedAt, seq)
	return err
}

// ApplyCredentialUsageGapTx records a window in which uses were lost.
func (s *Store) ApplyCredentialUsageGapTx(ctx context.Context, tx pgx.Tx, tenantID string, gap CredentialUsageGap, sequence uint64) error {
	if tenantID == "" || gap.ID == "" || gap.From.IsZero() || gap.To.Before(gap.From) || gap.Dropped <= 0 {
		return fmt.Errorf("store: credential usage gap is incomplete")
	}
	seq, err := usageSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO credential_usage_gaps (tenant_id, gap_id, from_at, to_at, dropped, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, gap_id) DO NOTHING`,
		tenantID, gap.ID, gap.From.UTC(), gap.To.UTC(), gap.Dropped, seq)
	return err
}

// CredentialUsageFor returns the recorded usage of the named credentials of one
// kind, keyed by credential ID; a credential with no recorded use is absent.
func (s *Store) CredentialUsageFor(ctx context.Context, tenantID, kind string, ids []string) (map[string]CredentialUsage, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: CredentialUsageFor requires a tenant id (AN-1)")
	}
	out := make(map[string]CredentialUsage, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT kind, credential_id, principal, first_used_at, last_used_at, last_source
			  FROM credential_usage WHERE tenant_id = $1 AND kind = $2 AND credential_id = ANY($3)`,
			tenantID, kind, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u CredentialUsage
			if err := rows.Scan(&u.Kind, &u.CredentialID, &u.Principal, &u.FirstUsedAt, &u.LastUsedAt, &u.LastSource); err != nil {
				return err
			}
			out[u.CredentialID] = u
		}
		return rows.Err()
	})
	return out, err
}

// ListCredentialUsage pages the tenant's recorded usage of one kind in
// credential ID order.
func (s *Store) ListCredentialUsage(ctx context.Context, tenantID, kind, afterID string, limit int) ([]CredentialUsage, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: ListCredentialUsage requires a tenant id (AN-1)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListCredentialUsage requires a positive limit")
	}
	var out []CredentialUsage
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT kind, credential_id, principal, first_used_at, last_used_at, last_source
			  FROM credential_usage WHERE tenant_id = $1 AND kind = $2 AND credential_id > $3
			 ORDER BY credential_id LIMIT $4`, tenantID, kind, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u CredentialUsage
			if err := rows.Scan(&u.Kind, &u.CredentialID, &u.Principal, &u.FirstUsedAt, &u.LastUsedAt, &u.LastSource); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// CredentialUsageSourcesFor returns every recorded source of the named
// credentials of one kind, keyed by credential ID, oldest source first.
func (s *Store) CredentialUsageSourcesFor(ctx context.Context, tenantID, kind string, ids []string) (map[string][]CredentialUsageSource, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: CredentialUsageSourcesFor requires a tenant id (AN-1)")
	}
	out := make(map[string][]CredentialUsageSource, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT credential_id, source_kind, source, first_seen_at, last_seen_at, days_seen
			  FROM credential_usage_sources WHERE tenant_id = $1 AND kind = $2 AND credential_id = ANY($3)
			 ORDER BY credential_id, first_seen_at, source`, tenantID, kind, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var src CredentialUsageSource
			if err := rows.Scan(&src.CredentialID, &src.SourceKind, &src.Source, &src.FirstSeenAt, &src.LastSeenAt, &src.DaysSeen); err != nil {
				return err
			}
			out[src.CredentialID] = append(out[src.CredentialID], src)
		}
		return rows.Err()
	})
	return out, err
}

// CredentialUsageTrackingSince is when trstctl began recording API-token use
// in the tenant: its first recorded use. Nil means nothing is recorded yet, so
// no token can be called unused.
func (s *Store) CredentialUsageTrackingSince(ctx context.Context, tenantID string) (*time.Time, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: CredentialUsageTrackingSince requires a tenant id (AN-1)")
	}
	var since *time.Time
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(first_used_at) FROM credential_usage WHERE tenant_id = $1 AND kind = $2`,
			tenantID, CredentialUsageAPIToken).Scan(&since)
	})
	return since, err
}

// CredentialUsageGapsOverlapping returns the recorded gaps that overlap
// [from, to].
func (s *Store) CredentialUsageGapsOverlapping(ctx context.Context, tenantID string, from, to time.Time) ([]CredentialUsageGap, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: CredentialUsageGapsOverlapping requires a tenant id (AN-1)")
	}
	var out []CredentialUsageGap
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT gap_id, from_at, to_at, dropped FROM credential_usage_gaps
			 WHERE tenant_id = $1 AND to_at >= $2 AND from_at <= $3
			 ORDER BY from_at, gap_id LIMIT 100`, tenantID, from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g CredentialUsageGap
			if err := rows.Scan(&g.ID, &g.From, &g.To, &g.Dropped); err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}
