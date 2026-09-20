// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ExternalCertificateRevocation selects one already verified public certificate.
// Projection queues it without changing certificate status or any local CA ledger.
type ExternalCertificateRevocation struct {
	EventID       string `json:"event_id"`
	CertificateID string `json:"certificate_id"`
	Fingerprint   string `json:"fingerprint"`
	Serial        string `json:"serial"`
	ExternalCAID  string `json:"external_ca_id"`
	Reason        string `json:"reason"`
}

func (s *Store) EnsureExternalCertificateRevocationTx(ctx context.Context, tx pgx.Tx, tenantID string, command ExternalCertificateRevocation) error {
	certificate, err := s.CertificateForRevocationTx(ctx, tx, tenantID, command.CertificateID)
	if err != nil {
		return err
	}
	if certificate.Fingerprint != command.Fingerprint || certificate.Serial != command.Serial {
		return fmt.Errorf("%w: external certificate revocation target changed", ErrIdempotencyConflict)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return err
	}
	const destination = "revocation.publish"
	key := "certificate.external-revoke:" + command.EventID + ":" + command.CertificateID
	lane := destination + ":authority:" + command.ExternalCAID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenantID+"\x1f"+key); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		SELECT $1,$2,$3,$4,$5 WHERE NOT EXISTS
		(SELECT 1 FROM outbox WHERE tenant_id=$1 AND idempotency_key=$5)`, tenantID, destination, lane, payload, key)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var existingDestination, existingLane string
	var existingPayload []byte
	if err := tx.QueryRow(ctx, `SELECT destination, COALESCE(NULLIF(effect_lane,''),destination), payload
		FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 ORDER BY id LIMIT 1`, tenantID, key).
		Scan(&existingDestination, &existingLane, &existingPayload); err != nil {
		return err
	}
	if existingDestination != destination || existingLane != lane || !bytes.Equal(existingPayload, payload) {
		return fmt.Errorf("%w: external certificate revocation command differs", ErrIdempotencyConflict)
	}
	return nil
}
