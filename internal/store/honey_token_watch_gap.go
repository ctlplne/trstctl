// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplyHoneyTokenWatchGapOpenedTx records that the watcher cannot read a
// decoy login (Q6-L10) and enqueues one warning for the gap: until it is
// read again, a use of the bait is not seen. A gap already open keeps its
// start, and a decoy that is no longer active records none.
func (s *Store) ApplyHoneyTokenWatchGapOpenedTx(ctx context.Context, tx pgx.Tx, tenantID, id, reason string, since time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE honey_tokens SET watch_gap_since = $3, watch_gap_reason = $4
		  WHERE tenant_id = $1 AND id = $2 AND state = 'active' AND watch_gap_since IS NULL`,
		tenantID, id, since.UTC(), reason)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	var name, placement string
	err = tx.QueryRow(ctx, `SELECT name, placement FROM honey_tokens WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&name, &placement)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	key := "honeytoken.watch_gap:" + id + ":" + strconv.FormatInt(since.UTC().UnixNano(), 10)
	alert, err := json.Marshal(map[string]any{
		"kind": "honeytoken.watch_gap", "tenant_id": tenantID, "operation_id": key,
		"subject": name, "severity": "warning",
		"detail": "trstctl cannot watch decoy " + id + " at placement " + placement + " since " +
			since.UTC().Format(time.RFC3339) + ": " + reason + ". A use of the bait is not seen until it is watched again.",
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 SELECT $1, 'notification.honeytoken', $2, $3
		  WHERE NOT EXISTS (SELECT 1 FROM outbox
		                     WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
		                       AND idempotency_key = $3)`, tenantID, alert, key)
	return err
}

// ApplyHoneyTokenWatchGapClosedTx records that the watcher reads the decoy
// again (Q6-L10).
func (s *Store) ApplyHoneyTokenWatchGapClosedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx,
		`UPDATE honey_tokens SET watch_gap_since = NULL, watch_gap_reason = NULL WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}
