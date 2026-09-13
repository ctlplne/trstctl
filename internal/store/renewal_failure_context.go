// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// RenewalFailureContext is metadata captured with the failed transition. The
// certificate is selected by completed delivery evidence, never by issuance
// recency. It describes a historical deployment, not a fresh listener probe.
type RenewalFailureContext struct {
	OwnerName, OwnerEmail                         string
	CertificateID, Serial, Fingerprint, ReceiptID string
	NotAfter, RecordedAt                          *time.Time
}

func (s *Store) RenewalFailureContextTx(ctx context.Context, tx pgx.Tx, identity Identity) (RenewalFailureContext, error) {
	var result RenewalFailureContext
	if identity.OwnerID != "" {
		err := tx.QueryRow(ctx, `SELECT name, email FROM owners WHERE tenant_id=$1 AND id=$2`, identity.TenantID, identity.OwnerID).Scan(&result.OwnerName, &result.OwnerEmail)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
	}
	// Select the last receipt before joining inventory. Missing certificate
	// metadata must not fall back to an older installation or another tenant.
	err := tx.QueryRow(ctx, `
		SELECT r.id::text, r.fingerprint, r.updated_at,
		       COALESCE(c.id::text,''), COALESCE(c.serial,''), c.not_after
		FROM (
		  SELECT id, tenant_id, fingerprint, updated_at FROM connector_delivery_receipts
		  WHERE tenant_id=$1 AND identity_id=$2 AND fingerprint<>''
		    AND ((destination='connector.deploy' AND status IN ('delivered','verified'))
		      OR (destination='connector.rollback' AND status='rolled_back'))
		  ORDER BY updated_at DESC, id DESC LIMIT 1
		) r
		LEFT JOIN certificates c ON c.tenant_id=$1 AND c.tenant_id=r.tenant_id AND c.fingerprint=r.fingerprint`,
		identity.TenantID, identity.ID).Scan(&result.ReceiptID, &result.Fingerprint, &result.RecordedAt, &result.CertificateID, &result.Serial, &result.NotAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	return result, err
}
