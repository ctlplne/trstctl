// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"strings"
)

// IdentityRenewalCSR follows only explicit same-tenant predecessor links to an
// exact issued transition of this identity. Owner/name similarity and mutable
// identity attributes cannot substitute for the original authorized CSR.
// All reads share one tenant transaction;64 links is an explicit bound. Missing,
// cyclic, ambiguous, unprojected or non-requester history refuses renewal.
func (s *Store) IdentityRenewalCSR(ctx context.Context, tenantID, identityID, certificateID string) (string, error) {
	var csr string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		seen := map[string]bool{}
		for depth := 0; depth < 64; depth++ {
			if certificateID == "" || seen[certificateID] {
				return errors.New("store: incomplete or cyclic requester renewal lineage")
			}
			seen[certificateID] = true
			var origin, key, eventID string
			var predecessor *string
			if err := tx.QueryRow(ctx, `SELECT key_origin,issuance_idempotency_key,issuance_event_id,replaces_id::text FROM certificates WHERE tenant_id=$1 AND id=$2`, tenantID, certificateID).Scan(&origin, &key, &eventID, &predecessor); err != nil {
				return err
			}
			if origin != "requester" {
				return errors.New("store: requester renewal lineage has different or unknown key custody")
			}
			if strings.HasPrefix(key, "issue:transition:") {
				if eventID == "" {
					return errors.New("store: requester renewal has no immutable issuance provenance")
				}
				requestKey := strings.TrimPrefix(key, "issue:transition:")
				rows, err := tx.Query(ctx, `SELECT subject_csr_pem FROM identity_transitions WHERE tenant_id=$1 AND identity_id=$2
                    AND idempotency_key=$3 AND event_type='identity.issued' AND from_state='requested' AND to_state='issued'
                    ORDER BY seq LIMIT 2`, tenantID, identityID, requestKey)
				if err != nil {
					return err
				}
				count := 0
				for rows.Next() {
					if err := rows.Scan(&csr); err != nil {
						rows.Close()
						return err
					}
					count++
				}
				err = rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
				if count != 1 || strings.TrimSpace(csr) == "" || len(csr) > 64*1024 {
					return errors.New("store: exact requester renewal transition CSR is missing or ambiguous")
				}
				return nil
			}
			if predecessor == nil {
				return errors.New("store: requester renewal has no exact lifecycle predecessor")
			}
			certificateID = *predecessor
		}
		return fmt.Errorf("store: requester renewal lineage exceeds64 certificates")
	})
	return csr, err
}
