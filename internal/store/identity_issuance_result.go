// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// IdentityIssuanceResult is a read of the exact accepted transition and its
// asynchronous certificate. Missing public material is not proof that its
// receiver command is still pending, or that the CA never signed anything.
type IdentityIssuanceResult struct {
	IdentityID  string
	RequestKey  string
	Certificate *Certificate
	Delivery    *IdentityIssuanceDelivery
}

// IdentityIssuanceDelivery exposes only safe bookkeeping from the exact
// accepted command. Receiver payloads and diagnostics remain private.
type IdentityIssuanceDelivery struct {
	Status   string
	Attempts int
}

// GetIdentityIssuanceResult never signs, drains work or replays the global log.
// The bounded reads use the same tenant/RLS transaction. A certificate key is
// derived only after the identity's own immutable transition proves that key.
func (s *Store) GetIdentityIssuanceResult(ctx context.Context, tenantID, identityID, requestKey string) (IdentityIssuanceResult, error) {
	requestKey = strings.TrimSpace(requestKey)
	result := IdentityIssuanceResult{IdentityID: identityID, RequestKey: requestKey}
	if requestKey == "" || len(requestKey) > 256 {
		return result, fmt.Errorf("store: bounded issuance request key required")
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq FROM identity_transitions
			WHERE tenant_id = $1 AND identity_id = $2 AND idempotency_key = $3
			  AND event_type = 'identity.issued' AND from_state = 'requested' AND to_state = 'issued'
			  AND idempotency_key <> ''
			ORDER BY seq LIMIT 2`, tenantID, identityID, requestKey)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var seq int64
			if err := rows.Scan(&seq); err != nil {
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
		if count == 0 {
			return pgx.ErrNoRows
		}
		if count != 1 {
			return ErrIdempotencyConflict
		}
		var delivery IdentityIssuanceDelivery
		var destination string
		var payload []byte
		err = tx.QueryRow(ctx, `SELECT status,attempts,destination,payload
			FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`,
			tenantID, "transition:"+requestKey).Scan(&delivery.Status, &delivery.Attempts, &destination, &payload)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			var command struct {
				IdentityID string `json:"identity_id"`
				To         string `json:"to"`
			}
			if json.Unmarshal(payload, &command) != nil || destination != "ca.issue" || command.IdentityID != identityID || command.To != "issued" || delivery.Attempts < 0 {
				return ErrIdempotencyConflict
			}
			switch delivery.Status {
			case "pending", "processing", "delivered", "failed", "cancelled":
			default:
				return fmt.Errorf("store: unknown issuance delivery state")
			}
			result.Delivery = &delivery
		}
		// Read the certificate after delivery bookkeeping. A receiver that
		// records its public result before failing must still expose that leaf.
		rows, err = tx.Query(ctx, `SELECT `+certificateColumns+` FROM certificates
			WHERE tenant_id = $1 AND issuance_idempotency_key = $2 ORDER BY id LIMIT 2`,
			tenantID, "issue:transition:"+requestKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if result.Certificate != nil {
				return ErrIdempotencyConflict
			}
			var cert Certificate
			if err := scanCertificate(rows, &cert); err != nil {
				return err
			}
			result.Certificate = &cert
		}
		return rows.Err()
	})
	return result, err
}
