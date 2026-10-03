// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// HoneyToken contains only decoy metadata and its one-way lookup hash. The raw
// bait credential exists solely in the reveal-once response.
type HoneyToken struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"-"`
	Name          string     `json:"name"`
	Placement     string     `json:"placement"`
	TokenHash     string     `json:"-"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	TriggeredAt   *time.Time `json:"triggered_at,omitempty"`
	TriggerMethod string     `json:"trigger_method,omitempty"`
	TriggerPath   string     `json:"trigger_path,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

// #nosec G101 -- SQL column names only; this string contains no credential material.
const honeyTokenColumns = `id::text, tenant_id::text, name, placement, token_hash, state,
    created_at, triggered_at, COALESCE(trigger_method, ''), COALESCE(trigger_path, ''), revoked_at`

func scanHoneyToken(row pgx.Row) (HoneyToken, error) {
	var h HoneyToken
	err := row.Scan(&h.ID, &h.TenantID, &h.Name, &h.Placement, &h.TokenHash,
		&h.State, &h.CreatedAt, &h.TriggeredAt, &h.TriggerMethod, &h.TriggerPath, &h.RevokedAt)
	return h, err
}

// LookupHoneyTokenByHash is the pre-tenant authentication exception. A 256-bit
// random bearer hash identifies exactly one tenant; no decoy can grant access.
func (s *Store) LookupHoneyTokenByHash(ctx context.Context, hash string) (HoneyToken, error) {
	return scanHoneyToken(s.pool.QueryRow(ctx,
		//trstctl:system-query — authentication runs before any tenant is known; the globally unique 256-bit bearer hash limits this system lookup to the owning tenant's inert decoy metadata (AN-1 exemption).
		`SELECT `+honeyTokenColumns+` FROM honey_tokens WHERE token_hash = $1 AND state <> 'revoked'`, hash))
}

func (s *Store) GetHoneyToken(ctx context.Context, tenantID, id string) (HoneyToken, error) {
	var h HoneyToken
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		h, err = scanHoneyToken(tx.QueryRow(ctx,
			`SELECT `+honeyTokenColumns+` FROM honey_tokens WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return err
	})
	return h, err
}

func (s *Store) ListHoneyTokensPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	out := make([]HoneyToken, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+honeyTokenColumns+` FROM honey_tokens
			 WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h HoneyToken
			if err := rows.Scan(&h.ID, &h.TenantID, &h.Name, &h.Placement, &h.TokenHash,
				&h.State, &h.CreatedAt, &h.TriggeredAt, &h.TriggerMethod, &h.TriggerPath, &h.RevokedAt); err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) ApplyHoneyTokenCreatedTx(ctx context.Context, tx pgx.Tx, h HoneyToken) error {
	if err := lockUpsertArbiterTx(ctx, tx, "honey_tokens", h.TenantID, h.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO honey_tokens (id, tenant_id, name, placement, token_hash, state, created_at)
		 VALUES ($1, $2, $3, $4, $5, 'active', $6)
		 ON CONFLICT (id) DO NOTHING`,
		h.ID, h.TenantID, h.Name, h.Placement, h.TokenHash, h.CreatedAt)
	return err
}

// ApplyHoneyTokenTriggeredTx changes state and enqueues one alert atomically.
// Concurrent stolen-bearer requests may append duplicate observations, but only
// the transition from active produces a notification.
func (s *Store) ApplyHoneyTokenTriggeredTx(ctx context.Context, tx pgx.Tx, tenantID, id, method, path string, at time.Time) error {
	var name, placement string
	err := tx.QueryRow(ctx,
		`UPDATE honey_tokens SET state = 'triggered', triggered_at = $3,
		 trigger_method = $4, trigger_path = $5
		 WHERE tenant_id = $1 AND id = $2 AND state = 'active'
		 RETURNING name, placement`,
		tenantID, id, at, method, path).Scan(&name, &placement)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	alert, err := json.Marshal(map[string]any{
		"kind": "honeytoken.triggered", "tenant_id": tenantID,
		"operation_id": "honeytoken.triggered:" + id,
		"subject":      name, "detail": "Decoy credential used; inspect honeytoken " + id + " at placement " + placement,
		"severity": "critical",
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1, 'notification.honeytoken', $2, $3)
		 ON CONFLICT DO NOTHING`, tenantID, alert, "honeytoken.triggered:"+id)
	return err
}

func (s *Store) ApplyHoneyTokenRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE honey_tokens SET state = 'revoked', revoked_at = COALESCE(revoked_at, $3)
		 WHERE tenant_id = $1 AND id = $2`, tenantID, id, at)
	return err
}
