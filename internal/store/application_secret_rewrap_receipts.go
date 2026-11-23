// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ApplicationSecretRewrapReceipt is the bounded non-secret receipt view used
// before changing a tenant's sealed wrappers. It never exposes ciphertext.
type ApplicationSecretRewrapReceipt struct {
	EventID   string
	DigestV1  string
	DigestV2  string
	RowSHA256 string
}

const ApplicationSecretRewrapReceiptPageLimit = 128

func (s *Store) ListApplicationSecretRewrapReceiptsPage(ctx context.Context, tenantID, afterEventID string) ([]ApplicationSecretRewrapReceipt, error) {
	if tenantID == "" {
		return nil, errors.New("store: tenant is required for secret receipt paging")
	}
	var page []ApplicationSecretRewrapReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT event_id::text, semantic_sha256, coalesce(semantic_sha256_v2, '')
			  FROM application_secret_mutation_receipts
			 WHERE tenant_id=$1 AND ($2='' OR event_id > $2::uuid)
			 ORDER BY application_secret_mutation_receipts.event_id LIMIT $3`, tenantID, afterEventID, ApplicationSecretRewrapReceiptPageLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var receipt ApplicationSecretRewrapReceipt
			if err := rows.Scan(&receipt.EventID, &receipt.DigestV1, &receipt.DigestV2); err != nil {
				return err
			}
			page = append(page, receipt)
		}
		return rows.Err()
	})
	return page, err
}

// BackfillApplicationSecretReceiptV2 changes exactly one previously verified
// v1-only receipt. The caller has matched the original event and authenticated
// its sealed fields before invoking this compare-and-set.
func (s *Store) BackfillApplicationSecretReceiptV2(ctx context.Context, tenantID, eventID, digestV1, digestV2 string) error {
	if tenantID == "" || eventID == "" || len(digestV1) != 64 || len(digestV2) != 64 {
		return errors.New("store: incomplete application-secret v2 backfill")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE application_secret_mutation_receipts
			   SET semantic_sha256_v2=$4
			 WHERE tenant_id=$1 AND event_id=$2 AND semantic_sha256=$3
			   AND semantic_sha256_v2 IS NULL`, tenantID, eventID, digestV1, digestV2)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: application-secret receipt changed during v2 backfill", ErrIdempotencyConflict)
		}
		return nil
	})
}
