// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// ConsumeMDMSCEPNonce atomically claims one signed Intune challenge nonce. The
// hash is tenant scoped; neither the JWS nor its raw nonce is stored. This is
// an operational command fence, not a derived certificate or audit read model.
// A committed claim remains spent even if the process crashes before issuance.
func (s *Store) ConsumeMDMSCEPNonce(ctx context.Context, tenantID, nonce string, validUntil time.Time) (bool, error) {
	if tenantID == "" || nonce == "" || validUntil.IsZero() {
		return false, errors.New("store: MDM SCEP nonce claim is incomplete")
	}
	digest := crypto.SHA256Hex([]byte(nonce))
	var claimed bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `
			INSERT INTO mdm_scep_nonce_fences (tenant_id, nonce_sha256, valid_until)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, nonce_sha256) DO NOTHING`, tenantID, digest, validUntil.UTC())
		if err != nil {
			return err
		}
		claimed = result.RowsAffected() == 1
		// Keep cleanup bounded. Retain each fence for a full day beyond the
		// challenge expiry and configured clock skew so modest host/database
		// clock differences cannot reopen a spent challenge.
		_, err = tx.Exec(ctx, `
			WITH stale AS (
				SELECT nonce_sha256 FROM mdm_scep_nonce_fences
				WHERE tenant_id = $1 AND valid_until < clock_timestamp() - interval '24 hours'
				ORDER BY valid_until LIMIT 32
			)
			DELETE FROM mdm_scep_nonce_fences AS fence USING stale
			WHERE fence.tenant_id = $1 AND fence.nonce_sha256 = stale.nonce_sha256`, tenantID)
		return err
	})
	return claimed, err
}
