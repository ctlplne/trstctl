// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/privacy"
)

// Decoy readers and privacy (Q6-L3). A secret decoy keeps its first reader,
// and its alerts in the outbox name every reader until the delivered rows
// leave the outbox. A subject's export lists the decoys they triggered, and
// an erasure clears the subject from both: the decoy's first reader and the
// text of that subject's alerts, delivered or still waiting. Other readers'
// alerts are left as they are.
//
// Each decoy also keeps its readers as one-way references with their reads
// (Q6-L1, honey_token_readers). The export lists every decoy the subject read
// with their own reads, and an erasure moves the subject's reader row to the
// reference of their placeholder: the erasure rewrites the reader of their
// read events to that placeholder, so a rebuild reaches the same row.

// decoyAlertKey is the per-reader alert key ApplyDecoySecretReadTx writes.
func decoyAlertKey(decoyID, reader string) string {
	return "honeytoken.secret_read:" + decoyID + ":" + crypto.SHA256Hex([]byte(reader))[:32]
}

func decoyPrivacySelectorQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{{
		table: "honey_tokens",
		sql: `SELECT h.id::text, ''::text, 0 FROM honey_tokens h
		       WHERE h.tenant_id = $1 AND h.kind = 'secret'
		         AND (h.trigger_subject = $2 OR EXISTS (
		              SELECT 1 FROM outbox o
		               WHERE o.tenant_id = h.tenant_id AND o.destination = 'notification.honeytoken'
		                 AND o.idempotency_key = 'honeytoken.secret_read:' || h.id::text || ':' || $3)
		          OR EXISTS (
		              SELECT 1 FROM honey_token_readers r
		               WHERE r.tenant_id = h.tenant_id AND r.honey_token_id = h.id AND r.reader_ref = $4))
		       ORDER BY h.id`,
		args: []any{tenantID, subject, crypto.SHA256Hex([]byte(subject))[:32], privacy.SubjectRef(tenantID, subject)},
	}}
}

func decoyPrivacyExportQueries(tenantID, subject string) []privacyReadModelQuery {
	return []privacyReadModelQuery{{
		table: "honey_tokens",
		sql: `SELECT h.id::text, ''::text,
		             (jsonb_build_object('secret_name', h.secret_name, 'state', h.state)
		              || CASE WHEN h.trigger_subject = $2 THEN
		                      jsonb_build_object('trigger_subject', h.trigger_subject, 'triggered_at', h.triggered_at,
		                                         'trigger_method', h.trigger_method, 'trigger_path', h.trigger_path)
		                 ELSE '{}'::jsonb END
		              || CASE WHEN r.reader_ref IS NOT NULL THEN
		                      jsonb_build_object('first_read_at', r.first_read_at, 'last_read_at', r.last_read_at, 'reads', r.reads)
		                 ELSE '{}'::jsonb END)::text,
		             h.created_at
		        FROM honey_tokens h
		        LEFT JOIN honey_token_readers r
		          ON r.tenant_id = h.tenant_id AND r.honey_token_id = h.id AND r.reader_ref = $3
		       WHERE h.tenant_id = $1 AND h.kind = 'secret' AND (h.trigger_subject = $2 OR r.reader_ref IS NOT NULL)
		       ORDER BY h.id`,
		args: []any{tenantID, subject, privacy.SubjectRef(tenantID, subject)},
	}}
}

// eraseDecoySecretPrivacyRows clears the erased subject from each selected
// decoy's first reader and from the text of that subject's alerts.
func eraseDecoySecretPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subjectRef, placeholder string, selectors []PrivacyReadModelSelector) error {
	for _, id := range readModelIDs(selectors, "honey_tokens") {
		var secretName, placement, trigger string
		err := tx.QueryRow(ctx,
			`SELECT COALESCE(secret_name, ''), placement, COALESCE(trigger_subject, '') FROM honey_tokens
			  WHERE tenant_id = $1 AND id::text = $2 AND kind = 'secret' FOR UPDATE`, tenantID, id).Scan(&secretName, &placement, &trigger)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if trigger != "" && subjectValueMatches(tenantID, subjectRef, trigger) {
			if _, err := tx.Exec(ctx, `UPDATE honey_tokens SET trigger_subject = $3 WHERE tenant_id = $1 AND id::text = $2`, tenantID, id, placeholder); err != nil {
				return err
			}
		}
		if err := eraseDecoyAlertReaders(ctx, tx, tenantID, id, secretName, placement, subjectRef, placeholder); err != nil {
			return err
		}
		if err := moveDecoyReaderToPlaceholderTx(ctx, tx, tenantID, id, subjectRef, placeholder); err != nil {
			return err
		}
	}
	return nil
}

// moveDecoyReaderToPlaceholderTx moves the erased subject's reader row of one
// decoy to the reference of their placeholder, merged with any row already
// there (a subject erased before who read again). The decoy keeps the count of
// its readers and reads, and nothing on it leads back to the subject.
func moveDecoyReaderToPlaceholderTx(ctx context.Context, tx pgx.Tx, tenantID, decoyID, subjectRef, placeholder string) error {
	_, err := tx.Exec(ctx,
		`WITH moved AS (
		     DELETE FROM honey_token_readers
		      WHERE tenant_id = $1 AND honey_token_id::text = $2 AND reader_ref = $3
		  RETURNING tenant_id, honey_token_id, first_read_at, last_read_at, reads)
		 INSERT INTO honey_token_readers (tenant_id, honey_token_id, reader_ref, first_read_at, last_read_at, reads)
		 SELECT tenant_id, honey_token_id, $4, first_read_at, last_read_at, reads FROM moved
		 ON CONFLICT (tenant_id, honey_token_id, reader_ref) DO UPDATE
		    SET first_read_at = LEAST(honey_token_readers.first_read_at, EXCLUDED.first_read_at),
		        last_read_at = GREATEST(honey_token_readers.last_read_at, EXCLUDED.last_read_at),
		        reads = honey_token_readers.reads + EXCLUDED.reads`,
		tenantID, decoyID, subjectRef, privacy.SubjectRef(tenantID, placeholder))
	return err
}

func eraseDecoyAlertReaders(ctx context.Context, tx pgx.Tx, tenantID, decoyID, secretName, placement, subjectRef, placeholder string) error {
	type alert struct {
		id      int64
		payload []byte
	}
	var alerts []alert
	rows, err := tx.Query(ctx,
		`SELECT id, payload FROM outbox
		  WHERE tenant_id = $1 AND destination = 'notification.honeytoken'
		    AND idempotency_key LIKE 'honeytoken.secret_read:' || $2 || ':%'
		  ORDER BY id FOR UPDATE`, tenantID, decoyID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var a alert
		if err := rows.Scan(&a.id, &a.payload); err != nil {
			rows.Close()
			return err
		}
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	prefix := "Decoy secret " + secretName + " was read by "
	suffix := "); inspect decoy " + decoyID + " at placement " + placement
	for _, a := range alerts {
		var payload map[string]any
		if err := json.Unmarshal(a.payload, &payload); err != nil {
			continue // not an alert this code wrote
		}
		detail, _ := payload["detail"].(string)
		if !strings.HasPrefix(detail, prefix) || !strings.HasSuffix(detail, suffix) || len(detail) < len(prefix)+len(suffix) {
			continue
		}
		middle := detail[len(prefix) : len(detail)-len(suffix)]
		cut := strings.LastIndex(middle, " (")
		if cut < 0 || !subjectValueMatches(tenantID, subjectRef, middle[:cut]) {
			continue
		}
		payload["detail"] = prefix + placeholder + middle[cut:] + suffix
		rewritten, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE outbox SET payload = $3 WHERE tenant_id = $1 AND id = $2`, tenantID, a.id, rewritten); err != nil {
			return err
		}
	}
	return nil
}
