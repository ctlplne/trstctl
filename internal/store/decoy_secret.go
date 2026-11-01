// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// Secret decoys (Q6): an application secret registered as bait. trstctl is in
// the read path, so every value read through the served API names its reader.
// Listing names, reading metadata and trstctl's own scans never read a value
// through that path and so never alert.

// LookupLiveDecoySecret returns the decoy watching the named secret, if one is
// active or already triggered. A retired decoy no longer watches.
func (s *Store) LookupLiveDecoySecret(ctx context.Context, tenantID, secretName string) (string, bool, error) {
	var id string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text FROM honey_tokens
			  WHERE tenant_id = $1 AND kind = 'secret' AND secret_name = $2 AND state <> 'revoked'
			  ORDER BY created_at, id LIMIT 1`, tenantID, secretName).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}

// ListDecoySecretsPage pages the tenant's secret decoys in id order.
func (s *Store) ListDecoySecretsPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	out := make([]HoneyToken, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+honeyTokenColumns+` FROM honey_tokens
			  WHERE tenant_id = $1 AND kind = 'secret' AND id::text > $2 ORDER BY id::text LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanHoneyToken(rows)
			if err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyDecoySecretReadTx projects one read of a secret decoy's value. The first
// read moves the decoy to triggered and keeps that reader; every distinct reader
// enqueues exactly one critical alert naming them, so a second thief is not
// hidden behind the first and a reader repeating the read is not re-alerted
// (until the delivered alert leaves the outbox at its retention). A retired
// decoy records nothing.
func (s *Store) ApplyDecoySecretReadTx(ctx context.Context, tx pgx.Tx, tenantID, id, reader, method, path string, at time.Time) error {
	if _, err := tx.Exec(ctx,
		`UPDATE honey_tokens SET state = 'triggered', triggered_at = $3,
		        trigger_method = $4, trigger_path = $5, trigger_subject = $6
		  WHERE tenant_id = $1 AND id = $2 AND kind = 'secret' AND state = 'active'`,
		tenantID, id, at, method, path, reader); err != nil {
		return err
	}
	var name, placement, secretName, state string
	err := tx.QueryRow(ctx,
		`SELECT name, placement, COALESCE(secret_name, ''), state FROM honey_tokens
		  WHERE tenant_id = $1 AND id = $2 AND kind = 'secret'`, tenantID, id).Scan(&name, &placement, &secretName, &state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "revoked") {
		return nil
	}
	if err != nil {
		return err
	}
	// The outbox carries no unique idempotency index (receivers collapse
	// retries), so one alert per reader is enforced here: serialize reads of
	// this decoy and enqueue only when no alert for this reader exists. The
	// outbox is not a read model, so a rebuild replaying these reads finds the
	// alerts already queued and adds none.
	if err := lockUpsertArbiterTx(ctx, tx, "honey_token_reader_alerts", tenantID, id); err != nil {
		return err
	}
	alertKey := "honeytoken.secret_read:" + id + ":" + crypto.SHA256Hex([]byte(reader))[:32]
	alert, err := json.Marshal(map[string]any{
		"kind": "honeytoken.triggered", "tenant_id": tenantID, "operation_id": alertKey,
		"subject": name, "severity": "critical",
		"detail": "Decoy secret " + secretName + " was read by " + reader + " (" + method + " " + path +
			"); inspect decoy " + id + " at placement " + placement,
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 SELECT $1, 'notification.honeytoken', $2, $3
		  WHERE NOT EXISTS (SELECT 1 FROM outbox
		                     WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
		                       AND idempotency_key = $3)`, tenantID, alert, alertKey)
	return err
}
