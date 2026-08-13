// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// CTCheckpoint records how far a CT log has been read for a tenant: the next
// tree index to fetch.
type CTCheckpoint struct {
	LogURL         string
	NextIndex      int64
	Active         bool
	ActivatedAt    time.Time
	RetiredAt      *time.Time
	LastPollStatus string
	LastPollError  string
	LastPolledAt   *time.Time
}

const (
	CTPollNever     = "never"
	CTPollSucceeded = "succeeded"
	CTPollFailed    = "failed"
)

// ErrCTLogNotActive means a poll tried to persist after its log was retired by
// a newer watchlist event. Refusing the write prevents an in-flight old poll
// from silently reactivating removed authority.
var ErrCTLogNotActive = errors.New("store: CT log is not active")

// AddWatchedDomain registers a domain the tenant wants watched in CT logs. It is
// idempotent: re-adding the same domain is a no-op.
func (s *Store) AddWatchedDomain(ctx context.Context, tenantID, domain string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ct_watched_domains (id, tenant_id, domain)
			 VALUES (gen_random_uuid(), $1, $2)
			 ON CONFLICT (tenant_id, domain) DO UPDATE
			 SET active = true,
			     activated_at = CASE WHEN ct_watched_domains.active THEN ct_watched_domains.activated_at ELSE now() END,
			     retired_at = NULL`,
			tenantID, domain)
		return err
	})
}

// ListWatchedDomains returns the tenant's watched domains, ordered.
func (s *Store) ListWatchedDomains(ctx context.Context, tenantID string) ([]string, error) {
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT domain FROM ct_watched_domains WHERE tenant_id = $1 AND active ORDER BY domain`, tenantID)
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
			 ON CONFLICT (tenant_id, log_url) DO UPDATE
			 SET active = true,
			     activated_at = CASE WHEN ct_log_checkpoints.active THEN ct_log_checkpoints.activated_at ELSE now() END,
			     retired_at = NULL`,
			tenantID, logURL)
		return err
	})
}

// ListCTLogCheckpoints returns the tenant's tracked CT logs and how far each has
// been read.
func (s *Store) ListCTLogCheckpoints(ctx context.Context, tenantID string) ([]CTCheckpoint, error) {
	return s.listCTLogCheckpoints(ctx, tenantID, true)
}

// ListCTLogCheckpointHistory returns active and retired rows. Schedulers use
// ListCTLogCheckpoints instead; this reader exists for operator audit evidence.
func (s *Store) ListCTLogCheckpointHistory(ctx context.Context, tenantID string) ([]CTCheckpoint, error) {
	return s.listCTLogCheckpoints(ctx, tenantID, false)
}

func (s *Store) listCTLogCheckpoints(ctx context.Context, tenantID string, activeOnly bool) ([]CTCheckpoint, error) {
	var out []CTCheckpoint
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT log_url, next_index, active, activated_at, retired_at,
			        last_poll_status, last_poll_error, last_polled_at
			   FROM ct_log_checkpoints
			  WHERE tenant_id = $1 AND (NOT $2::boolean OR active)
			  ORDER BY log_url`, tenantID, activeOnly)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CTCheckpoint
			if err := rows.Scan(
				&c.LogURL, &c.NextIndex, &c.Active, &c.ActivatedAt, &c.RetiredAt,
				&c.LastPollStatus, &c.LastPollError, &c.LastPolledAt,
			); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// SaveCTLogCheckpoint records the next index for an active (tenant, log). The
// event-projected watchlist must register it first.
func (s *Store) SaveCTLogCheckpoint(ctx context.Context, tenantID, logURL string, nextIndex int64) error {
	return s.SaveCTLogPollResult(ctx, tenantID, logURL, nextIndex, CTPollSucceeded, "")
}

// SaveCTLogPollResult persists one active log's latest poll truth. Successful
// progress advances the checkpoint; failure keeps the old checkpoint and saves
// a bounded diagnostic. A retired log is never re-created or reactivated here.
func (s *Store) SaveCTLogPollResult(ctx context.Context, tenantID, logURL string, nextIndex int64, status, detail string) error {
	status, detail, err := normalizeCTPollResult(nextIndex, status, detail)
	if err != nil {
		return err
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.applyCTLogPollResultTx(ctx, tx, tenantID, "", logURL, nextIndex, status, detail, time.Now().UTC(), true)
	})
}

// ApplyCTLogPollResultFromEventTx projects one per-log result carried by a
// discovery.run.completed event. The SQL proves the completed run belongs to a
// CT source that still names this log. If replacement retired the log while an
// old poll was in flight, the immutable event remains evidence but no stale
// completion can resurrect or overwrite the new active set.
func (s *Store) ApplyCTLogPollResultFromEventTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, runID, logURL string,
	nextIndex int64,
	status, detail string,
	observedAt time.Time,
) error {
	if strings.TrimSpace(runID) == "" {
		return errors.New("store: CT poll result run id is required")
	}
	if observedAt.IsZero() {
		return errors.New("store: CT poll result observation time is required")
	}
	status, detail, err := normalizeCTPollResult(nextIndex, status, detail)
	if err != nil {
		return err
	}
	return s.applyCTLogPollResultTx(ctx, tx, tenantID, runID, logURL, nextIndex, status, detail, observedAt, false)
}

func (s *Store) applyCTLogPollResultTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, runID, logURL string,
	nextIndex int64,
	status, detail string,
	observedAt time.Time,
	requireActive bool,
) error {
	var affected int64
	if runID == "" {
		tag, err := tx.Exec(ctx,
			`UPDATE ct_log_checkpoints
			    SET next_index = CASE WHEN $4 = 'succeeded' THEN GREATEST(next_index, $3) ELSE next_index END,
			        last_poll_status = $4,
			        last_poll_error = $5,
			        last_polled_at = $6,
			        updated_at = $6
			  WHERE tenant_id = $1 AND log_url = $2 AND active`,
			tenantID, logURL, nextIndex, status, detail, observedAt)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx,
			`UPDATE ct_log_checkpoints
			    SET next_index = CASE WHEN $4 = 'succeeded' THEN GREATEST(next_index, $3) ELSE next_index END,
			        last_poll_status = $4,
			        last_poll_error = $5,
			        last_polled_at = $6,
			        updated_at = $6
			  WHERE tenant_id = $1 AND log_url = $2 AND active
			    AND EXISTS (
			      SELECT 1
			        FROM discovery_runs run
			        JOIN discovery_sources source
			          ON source.tenant_id = run.tenant_id AND source.id = run.source_id
			       WHERE run.tenant_id = $1 AND run.id = $7::uuid
			         AND source.tenant_id = $1 AND source.kind = 'ct_log'
			         AND (source.config->>'log' = $2 OR
			              COALESCE(source.config->'logs', '[]'::jsonb) @> jsonb_build_array($2::text))
			    )`,
			tenantID, logURL, nextIndex, status, detail, observedAt, runID)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
	}
	if affected != 1 && requireActive {
		return fmt.Errorf("%w: %s", ErrCTLogNotActive, logURL)
	}
	return nil
}

func normalizeCTPollResult(nextIndex int64, status, detail string) (string, string, error) {
	if nextIndex < 0 {
		return "", "", errors.New("store: CT poll checkpoint must be non-negative")
	}
	if status != CTPollSucceeded && status != CTPollFailed {
		return "", "", fmt.Errorf("store: invalid CT poll status %q", status)
	}
	if status == CTPollSucceeded {
		detail = ""
	}
	detail = strings.ToValidUTF8(strings.TrimSpace(detail), "�")
	if len(detail) > 1024 {
		detail = detail[:1024]
		for !utf8.ValidString(detail) {
			detail = detail[:len(detail)-1]
		}
	}
	return status, detail, nil
}
