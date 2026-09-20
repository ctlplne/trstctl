// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
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
	RotationRunID                                 string
	RenewalJobID                                  int64
	RenewalAttempt                                int
}

// RenewalAttempt identifies a report's authenticated host-job claim. A run is
// resolved from that job's retained intent, never from the identity's latest run.
type RenewalAttempt struct {
	JobID   int64
	Attempt int
}

// RenewalFailureExecutionTx binds a warning to the exact queued command while
// the caller holds the identity lock. It only reads command metadata; private
// material and raw agent diagnostics are never returned to the notification.
func (s *Store) RenewalFailureExecutionTx(ctx context.Context, tx pgx.Tx, identity Identity, attempt RenewalAttempt) (RenewalFailureContext, error) {
	var result RenewalFailureContext
	if attempt.JobID <= 0 || attempt.Attempt <= 0 {
		return result, errors.New("renewal failure has an invalid job attempt")
	}
	var payload []byte
	var key string
	err := tx.QueryRow(ctx, `SELECT payload, idempotency_key FROM outbox
		WHERE tenant_id=$1 AND id=$2 AND destination='endpoint.renew' AND claim_attempts=$3`,
		identity.TenantID, attempt.JobID, attempt.Attempt).Scan(&payload, &key)
	if err != nil {
		return result, err
	}
	var intent struct {
		IdentityID               string `json:"identity_id"`
		RotationRunID            string `json:"rotation_run_id"`
		PredecessorCertificateID string `json:"predecessor_certificate_id"`
	}
	if json.Unmarshal(payload, &intent) != nil || intent.IdentityID != identity.ID {
		return result, errors.New("renewal failure differs from its queued identity")
	}
	result.RenewalJobID, result.RenewalAttempt = attempt.JobID, attempt.Attempt
	if intent.RotationRunID == "" {
		// Legacy jobs can identify an attempt, but have no retained run binding.
		return result, nil
	}
	var bound bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM lifecycle_rotation_runs r
		JOIN certificates c ON c.tenant_id=$1 AND c.fingerprint=r.predecessor_fingerprint
		WHERE r.tenant_id=$1 AND r.id=$2 AND r.identity_id=$3
		AND c.id=$4 AND $5='host-renew:renew:' || r.idempotency_key
	)`, identity.TenantID, intent.RotationRunID, identity.ID, intent.PredecessorCertificateID, key).Scan(&bound)
	if err != nil {
		return result, err
	}
	if !bound {
		return result, errors.New("renewal failure differs from its queued run or predecessor")
	}
	result.RotationRunID = intent.RotationRunID
	return result, nil
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
