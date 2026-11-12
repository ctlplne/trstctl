// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
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

// ApplyDecoySecretReadTx projects one read of a decoy that names its reader: a
// secret decoy's value read through the API (Q6), or a decoy file opened on its
// host, the reader being the opening program on that host (Q6-O1). The first
// read moves the decoy to triggered and keeps that reader; every distinct reader
// enqueues exactly one critical alert naming them, so a second thief is not
// hidden behind the first, and a reader repeating the read is not re-alerted,
// however long after (Q6-L1): the decoy's readers are kept in
// honey_token_readers as one-way references with their reads. A retired decoy
// records nothing.
func (s *Store) ApplyDecoySecretReadTx(ctx context.Context, tx pgx.Tx, tenantID, id, reader, method, path string, at time.Time) error {
	if _, err := tx.Exec(ctx,
		`UPDATE honey_tokens SET state = 'triggered', triggered_at = $3,
		        trigger_method = $4, trigger_path = $5, trigger_subject = $6
		  WHERE tenant_id = $1 AND id = $2 AND kind IN ('secret', 'file') AND state = 'active'`,
		tenantID, id, at, method, path, reader); err != nil {
		return err
	}
	var name, placement, kind, secretName, fileHost, filePath, state string
	err := tx.QueryRow(ctx,
		`SELECT name, placement, kind, COALESCE(secret_name, ''), COALESCE(file_host, ''), COALESCE(file_path, ''), state
		   FROM honey_tokens
		  WHERE tenant_id = $1 AND id = $2 AND kind IN ('secret', 'file')`, tenantID, id).Scan(&name, &placement, &kind, &secretName, &fileHost, &filePath, &state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "revoked") {
		return nil
	}
	if err != nil {
		return err
	}
	// One alert per reader: serialize reads of this decoy, record the read
	// against its reader, and alert only for a reader seen for the first time.
	// The reader record is a read model, so it outlives the alert's outbox row
	// (reclaimed a day after delivery) and a rebuild reconstructs it from the
	// reads. The outbox carries no unique idempotency index (receivers
	// collapse retries) and is not a read model, so the alert is also enqueued
	// only when none for this reader is queued: a rebuild replaying a first
	// read whose alert is still in the outbox adds none.
	if err := lockUpsertArbiterTx(ctx, tx, "honey_token_reader_alerts", tenantID, id); err != nil {
		return err
	}
	firstRead, err := recordDecoySecretReaderTx(ctx, tx, tenantID, id, reader, at)
	if err != nil || !firstRead {
		return err
	}
	alertKey := decoyAlertKey(id, reader)
	detail := "Decoy secret " + secretName + " was read by " + reader + " (" + method + " " + path +
		"); inspect decoy " + id + " at placement " + placement
	if kind == "file" {
		detail = "Decoy file " + filePath + " on " + fileHost + " was opened by " + reader + " (" + method +
			"); inspect decoy " + id + " at placement " + placement
	}
	alert, err := json.Marshal(map[string]any{
		"kind": "honeytoken.triggered", "tenant_id": tenantID, "operation_id": alertKey,
		"subject": name, "severity": "critical", "detail": detail,
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

// recordDecoySecretReaderTx counts one read of a secret decoy against its
// reader, kept as the reader's tenant-bound one-way reference, and reports
// whether it is the reader's first (Q6-L1). The caller holds the decoy's read
// lock.
func recordDecoySecretReaderTx(ctx context.Context, tx pgx.Tx, tenantID, id, reader string, at time.Time) (bool, error) {
	ref := privacy.SubjectRef(tenantID, reader)
	tag, err := tx.Exec(ctx,
		`INSERT INTO honey_token_readers (tenant_id, honey_token_id, reader_ref, first_read_at, last_read_at, reads)
		 VALUES ($1, $2, $3, $4, $4, 1)
		 ON CONFLICT (tenant_id, honey_token_id, reader_ref) DO NOTHING`, tenantID, id, ref, at)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	_, err = tx.Exec(ctx,
		`UPDATE honey_token_readers
		    SET first_read_at = LEAST(first_read_at, $4), last_read_at = GREATEST(last_read_at, $4), reads = reads + 1
		  WHERE tenant_id = $1 AND honey_token_id = $2 AND reader_ref = $3`, tenantID, id, ref, at)
	return false, err
}

// TenantsWithActiveDatabaseDecoys enumerates tenants holding an untriggered
// decoy database login, so the leader-only watcher can visit each tenant under
// its own RLS context.
func (s *Store) TenantsWithActiveDatabaseDecoys(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an active decoy database login so the leader-only watcher can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM honey_tokens WHERE kind = 'database' AND state = 'active' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// ListActiveDatabaseDecoys returns the tenant's untriggered decoy database
// logins, the ones the watcher still checks.
func (s *Store) ListActiveDatabaseDecoys(ctx context.Context, tenantID string) ([]HoneyToken, error) {
	return s.listHoneyTokensWhere(ctx, tenantID, `kind = 'database' AND state = 'active'`, "", 1000)
}

// ListDatabaseDecoysPage pages the tenant's decoy database logins in id order.
func (s *Store) ListDatabaseDecoysPage(ctx context.Context, tenantID, afterID string, limit int) ([]HoneyToken, error) {
	return s.listHoneyTokensWhere(ctx, tenantID, `kind = 'database'`, afterID, limit)
}

func (s *Store) listHoneyTokensWhere(ctx context.Context, tenantID, where, afterID string, limit int) ([]HoneyToken, error) {
	out := make([]HoneyToken, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+honeyTokenColumns+` FROM honey_tokens
			  WHERE tenant_id = $1 AND `+where+` AND id::text > $2 ORDER BY id::text LIMIT $3`, tenantID, afterID, limit)
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
