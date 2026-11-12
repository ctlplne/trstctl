// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CodeSigningTransparencyEntry is the Rekor entry a signing operation landed
// in (P9-L2), the projection of codesign.transparency_recorded: the logged
// body (base64), its index and time, the log's ID and its signed entry
// timestamp, as the Rekor handler verified them.
type CodeSigningTransparencyEntry struct {
	TenantID             string
	OperationID          string
	EntryUUID            string
	LogIndex             int64
	LogID                string
	IntegratedTime       int64
	Body                 string
	SignedEntryTimestamp []byte
	RecordedAt           time.Time
}

// ApplyCodeSigningTransparencyRecordedTx keeps an operation's transparency
// entry; an older event replayed after a newer one changes nothing.
func (s *Store) ApplyCodeSigningTransparencyRecordedTx(ctx context.Context, tx pgx.Tx, e CodeSigningTransparencyEntry, eventSequence uint64) error {
	if e.TenantID == "" || e.OperationID == "" || e.EntryUUID == "" || e.LogID == "" || e.Body == "" || len(e.SignedEntryTimestamp) == 0 {
		return errors.New("store: a transparency entry needs its tenant, operation, entry, log, body and signed entry timestamp")
	}
	if eventSequence == 0 || eventSequence > 1<<62 {
		return fmt.Errorf("store: transparency entry event sequence %d is out of range", eventSequence)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO code_signing_transparency_entries
		        (tenant_id, operation_id, entry_uuid, log_index, log_id, integrated_time, body, signed_entry_timestamp,
		         recorded_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, operation_id) DO UPDATE
		    SET entry_uuid = EXCLUDED.entry_uuid, log_index = EXCLUDED.log_index, log_id = EXCLUDED.log_id,
		        integrated_time = EXCLUDED.integrated_time, body = EXCLUDED.body,
		        signed_entry_timestamp = EXCLUDED.signed_entry_timestamp, recorded_at = EXCLUDED.recorded_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE code_signing_transparency_entries.event_sequence < EXCLUDED.event_sequence`,
		e.TenantID, e.OperationID, e.EntryUUID, e.LogIndex, e.LogID, e.IntegratedTime, e.Body, e.SignedEntryTimestamp,
		e.RecordedAt, int64(eventSequence)) // #nosec G115 -- bounded above (CWE-190)
	return err
}

// GetCodeSigningTransparencyEntry returns an operation's transparency entry,
// or an error IsNotFound reports when none was recorded.
func (s *Store) GetCodeSigningTransparencyEntry(ctx context.Context, tenantID, operationID string) (CodeSigningTransparencyEntry, error) {
	var out CodeSigningTransparencyEntry
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, entry_uuid, log_index, log_id, integrated_time, body,
			        signed_entry_timestamp, recorded_at
			   FROM code_signing_transparency_entries WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID).Scan(
			&out.TenantID, &out.OperationID, &out.EntryUUID, &out.LogIndex, &out.LogID, &out.IntegratedTime, &out.Body,
			&out.SignedEntryTimestamp, &out.RecordedAt)
	})
	if err != nil {
		return CodeSigningTransparencyEntry{}, err
	}
	return out, nil
}
