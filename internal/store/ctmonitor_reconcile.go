// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type projectedCTSourceConfig struct {
	Log            string   `json:"log"`
	Logs           []string `json:"logs"`
	Domain         string   `json:"domain"`
	WatchedDomains []string `json:"watched_domains"`
}

// reconcileCTMonitoringFromSourcesTx derives the tenant's active CT watchlist
// from every projected ct_log source. Because the source row and this derived
// polling authority change in one transaction, readers see either the old set
// or the complete replacement, never an append-only mixture (AN-2).
func (s *Store) reconcileCTMonitoringFromSourcesTx(ctx context.Context, tx pgx.Tx, tenantID string, changedAt time.Time) error {
	if changedAt.IsZero() {
		return errors.New("store: CT watchlist reconciliation time is required")
	}
	rows, err := tx.Query(ctx,
		`SELECT config FROM discovery_sources WHERE tenant_id = $1 AND kind = 'ct_log' ORDER BY id`,
		tenantID)
	if err != nil {
		return err
	}
	defer rows.Close()

	logSet := map[string]struct{}{}
	domainSet := map[string]struct{}{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var cfg projectedCTSourceConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("store: decode projected CT source config: %w", err)
		}
		addProjectedCTValue(logSet, cfg.Log)
		for _, value := range cfg.Logs {
			addProjectedCTValue(logSet, value)
		}
		addProjectedCTValue(domainSet, cfg.Domain)
		for _, value := range cfg.WatchedDomains {
			addProjectedCTValue(domainSet, value)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	logs := sortedProjectedCTValues(logSet)
	domains := sortedProjectedCTValues(domainSet)
	if _, err := tx.Exec(ctx,
		`UPDATE ct_log_checkpoints
		    SET active = false, retired_at = $3, updated_at = $3
		  WHERE tenant_id = $1 AND active AND NOT (log_url = ANY($2::text[]))`,
		tenantID, logs, changedAt); err != nil {
		return err
	}
	for _, logURL := range logs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO ct_log_checkpoints
			        (tenant_id, log_url, next_index, activated_at, updated_at)
			 VALUES ($1, $2, 0, $3, $3)
			 ON CONFLICT (tenant_id, log_url) DO UPDATE
			 SET active = true,
			     activated_at = CASE WHEN ct_log_checkpoints.active THEN ct_log_checkpoints.activated_at ELSE $3 END,
			     retired_at = NULL,
			     updated_at = $3`,
			tenantID, logURL, changedAt); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE ct_watched_domains
		    SET active = false, retired_at = $3
		  WHERE tenant_id = $1 AND active AND NOT (domain = ANY($2::text[]))`,
		tenantID, domains, changedAt); err != nil {
		return err
	}
	for _, domain := range domains {
		if err := lockUpsertArbiterTx(ctx, tx, "ct_watched_domains", tenantID, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ct_watched_domains (id, tenant_id, domain, activated_at, created_at)
			 VALUES (gen_random_uuid(), $1, $2, $3, $3)
			 ON CONFLICT (tenant_id, domain) DO UPDATE
			 SET active = true,
			     activated_at = CASE WHEN ct_watched_domains.active THEN ct_watched_domains.activated_at ELSE $3 END,
			     retired_at = NULL`,
			tenantID, domain, changedAt); err != nil {
			return err
		}
	}
	return nil
}

func addProjectedCTValue(values map[string]struct{}, value string) {
	if value = strings.TrimSpace(value); value != "" {
		values[value] = struct{}{}
	}
}

func sortedProjectedCTValues(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
