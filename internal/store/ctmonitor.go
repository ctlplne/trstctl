package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// CTCheckpoint records how far a CT log has been read for a tenant: the next
// tree index to fetch.
type CTCheckpoint struct {
	LogURL    string
	NextIndex int64
}

// AddWatchedDomain registers a domain the tenant wants watched in CT logs. It is
// idempotent: re-adding the same domain is a no-op.
func (s *Store) AddWatchedDomain(ctx context.Context, tenantID, domain string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ct_watched_domains (id, tenant_id, domain)
			 VALUES (gen_random_uuid(), $1, $2)
			 ON CONFLICT (tenant_id, domain) DO NOTHING`,
			tenantID, domain)
		return err
	})
}

// ListWatchedDomains returns the tenant's watched domains, ordered.
func (s *Store) ListWatchedDomains(ctx context.Context, tenantID string) ([]string, error) {
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT domain FROM ct_watched_domains WHERE tenant_id = $1 ORDER BY domain`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// RegisterCTLog begins tracking a CT log for the tenant, starting at index 0. It
// is idempotent: an already-tracked log keeps its checkpoint.
func (s *Store) RegisterCTLog(ctx context.Context, tenantID, logURL string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ct_log_checkpoints (tenant_id, log_url, next_index)
			 VALUES ($1, $2, 0)
			 ON CONFLICT (tenant_id, log_url) DO NOTHING`,
			tenantID, logURL)
		return err
	})
}

// ListCTLogCheckpoints returns the tenant's tracked CT logs and how far each has
// been read.
func (s *Store) ListCTLogCheckpoints(ctx context.Context, tenantID string) ([]CTCheckpoint, error) {
	var out []CTCheckpoint
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT log_url, next_index FROM ct_log_checkpoints WHERE tenant_id = $1 ORDER BY log_url`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CTCheckpoint
			if err := rows.Scan(&c.LogURL, &c.NextIndex); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// SaveCTLogCheckpoint records the next index to read for a (tenant, log),
// creating the row if the log was not yet tracked.
func (s *Store) SaveCTLogCheckpoint(ctx context.Context, tenantID, logURL string, nextIndex int64) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ct_log_checkpoints (tenant_id, log_url, next_index, updated_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (tenant_id, log_url)
			 DO UPDATE SET next_index = EXCLUDED.next_index, updated_at = now()`,
			tenantID, logURL, nextIndex)
		return err
	})
}
