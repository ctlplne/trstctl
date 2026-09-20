// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// LatestIdentityDeploymentReceipt returns historical completion evidence, not a
// fresh listener probe. Unlike renewal eligibility, this read must retain revoked
// and superseded certificates: hiding them would erase what was installed.
// Failed/queued attempts and another identity with the same name cannot replace
// the selected identity's last completed deployment or rollback.
func (s *Store) LatestIdentityDeploymentReceipt(ctx context.Context, tenantID, identityID string) (ConnectorDeliveryReceipt, bool, error) {
	var receipt ConnectorDeliveryReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanConnectorDeliveryReceipt(tx.QueryRow(ctx, `
			SELECT id::text, tenant_id::text, outbox_id, identity_id::text, destination,
			       connector, target, fingerprint, status, attempts, reason, detail,
			       rollback_ref, idempotency_key, created_at, updated_at
			FROM connector_delivery_receipts
			WHERE tenant_id=$1 AND identity_id=$2 AND fingerprint<>''
			  AND ((destination='connector.deploy' AND status IN ('delivered','verified'))
			    OR (destination='connector.rollback' AND status='rolled_back'))
			ORDER BY updated_at DESC, id DESC LIMIT 1`, tenantID, identityID), &receipt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectorDeliveryReceipt{}, false, nil
	}
	return receipt, err == nil, err
}
