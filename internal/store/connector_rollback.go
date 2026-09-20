// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrUnsafeRollback means current inventory cannot authorize restoration. An
// unknown predecessor is refused as well: absence is not proof of non-revocation.
var ErrUnsafeRollback = errors.New("rollback refused: predecessor is missing or revoked, or its identity is revoked or retired; issue a replacement certificate")

// CheckConnectorRollbackTx keeps the identity and exact predecessor stable until
// the caller commits its queue or lease decision. Superseded certificates are
// eligible; revocation must never be undone by selecting an older deployment.
func (s *Store) CheckConnectorRollbackTx(ctx context.Context, tx pgx.Tx, tenantID, identityID, fingerprint string) error {
	if identityID = strings.TrimSpace(identityID); identityID != "" {
		var state string
		err := tx.QueryRow(ctx, `SELECT status FROM identities WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenantID, identityID).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnsafeRollback
		}
		if err != nil {
			return err
		}
		if state == "revoked" || state == "retired" {
			return ErrUnsafeRollback
		}
	}
	var state string
	var revoked bool
	err := tx.QueryRow(ctx, `SELECT status, revoked_at IS NOT NULL FROM certificates WHERE tenant_id=$1 AND fingerprint=$2 FOR SHARE`, tenantID, strings.TrimSpace(fingerprint)).Scan(&state, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnsafeRollback
	}
	if err != nil {
		return err
	}
	if revoked || (state != "active" && state != "superseded") {
		return ErrUnsafeRollback
	}
	return nil
}

// CheckConnectorRollbackPayload checks the durable command, not agent-supplied
// fields. It is repeated at claim and immediately before credential release.
func (s *Store) CheckConnectorRollbackPayload(ctx context.Context, tenantID string, payload []byte) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return s.checkConnectorRollbackPayloadTx(ctx, tx, tenantID, payload)
	})
}

func (s *Store) checkConnectorRollbackPayloadTx(ctx context.Context, tx pgx.Tx, tenantID string, payload []byte) error {
	var in struct {
		IdentityID             string `json:"identity_id"`
		PredecessorFingerprint string `json:"predecessor_fingerprint"`
	}
	if json.Unmarshal(payload, &in) != nil || strings.TrimSpace(in.PredecessorFingerprint) == "" {
		return ErrUnsafeRollback
	}
	return s.CheckConnectorRollbackTx(ctx, tx, tenantID, in.IdentityID, in.PredecessorFingerprint)
}
