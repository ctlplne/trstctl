// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// selectAttesterTrustReceiptPrivacyRows identifies only opaque receipt IDs for
// the durable privacy event. The raw subject never enters event selectors.
func selectAttesterTrustReceiptPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, subject string) ([]PrivacyReadModelSelector, error) {
	rows, err := tx.Query(ctx, `SELECT event_id::text,response_snapshot
		FROM workload_attester_trust_receipts
		WHERE tenant_id=$1 AND response_snapshot IS NOT NULL
		ORDER BY event_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var selected []PrivacyReadModelSelector
	for rows.Next() {
		var eventID string
		var snapshot []byte
		if err := rows.Scan(&eventID, &snapshot); err != nil {
			return nil, err
		}
		if _, changed := events.PseudonymizeDataForSubject(snapshot, tenantID, subject); changed {
			selected = append(selected, PrivacyReadModelSelector{Table: "workload_attester_trust_receipts", ID: eventID})
		}
	}
	return selected, rows.Err()
}

// eraseAttesterTrustReceiptPrivacyRows drops only the response copy. The
// one-way request binding stays so a privacy-erased old key cannot re-execute.
func eraseAttesterTrustReceiptPrivacyRows(ctx context.Context, tx pgx.Tx, tenantID, _, _ string, selectors []PrivacyReadModelSelector) error {
	ids := readModelIDs(selectors, "workload_attester_trust_receipts")
	if len(ids) == 0 {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE workload_attester_trust_receipts
		SET response_snapshot=NULL WHERE tenant_id=$1 AND event_id::text=ANY($2::text[])`, tenantID, ids)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return fmt.Errorf("%w: selected attester trust receipt is missing", ErrIdempotencyConflict)
	}
	return nil
}
