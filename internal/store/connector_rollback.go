// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
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
		SuccessorFingerprint   string `json:"successor_fingerprint"`
		PQCRunID               string `json:"pqc_run_id"`
		PQCAssetID             string `json:"pqc_asset_id"`
		TargetID               string `json:"target_id"`
		TargetRevision         string `json:"target_revision"`
		Connector              string `json:"connector"`
		RequiredAgentID        string `json:"required_agent_id"`
		VerifyAddress          string `json:"verify_address"`
		VerifyServerName       string `json:"verify_server_name"`
	}
	if json.Unmarshal(payload, &in) != nil || strings.TrimSpace(in.PredecessorFingerprint) == "" {
		return ErrUnsafeRollback
	}
	if in.PQCRunID != "" || in.PQCAssetID != "" {
		// An unmanaged predecessor cannot appear in certificates. The PQC
		// rollback API admits it only from a retained, signed host-applied
		// event. At every later claim and authorization, recheck the *current*
		// successor, exact target revision and host assignment. The enrolled
		// agent will open only the predecessor it pinned for this run and will
		// sign a fresh listener readback before completion. Ordinary rollback
		// retains the stricter inventoried-predecessor rule below.
		if in.PQCRunID == "" || in.PQCAssetID == "" || in.IdentityID == "" || in.TargetID == "" ||
			in.TargetRevision == "" || in.Connector == "" || in.RequiredAgentID == "" ||
			in.VerifyAddress == "" || in.VerifyServerName == "" ||
			in.SuccessorFingerprint == "" || in.SuccessorFingerprint == in.PredecessorFingerprint {
			return ErrUnsafeRollback
		}
		for _, id := range []string{in.PQCRunID, in.PQCAssetID, in.IdentityID, in.TargetID, in.RequiredAgentID} {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed.String() != id {
				return ErrUnsafeRollback
			}
		}
		if err := validateCryptoAssetFingerprint(CryptoAsset{Kind: "certificate-key", CertificateFingerprint: in.SuccessorFingerprint}); err != nil {
			return ErrUnsafeRollback
		}
		if err := validateCryptoAssetFingerprint(CryptoAsset{Kind: "certificate-key", CertificateFingerprint: in.PredecessorFingerprint}); err != nil {
			return ErrUnsafeRollback
		}
		var eligible bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM crypto_assets asset
			  JOIN deployment_targets target ON target.tenant_id = asset.tenant_id AND target.id = $5::uuid
			  JOIN identities identity ON identity.tenant_id = asset.tenant_id AND identity.id = $7::uuid
			  JOIN certificates successor ON successor.tenant_id = asset.tenant_id AND successor.fingerprint = $4
			 WHERE asset.tenant_id = $1 AND asset.id = $2::uuid AND asset.kind = 'certificate-key'
			   AND asset.is_active AND asset.location = $3 AND asset.certificate_fingerprint = $4
			   AND target.revision_id = $6 AND target.type = $8 AND target.enabled
			   AND target.config->>'executor' = 'agent'
			   AND target.config->>'required_agent_id' = $9
			   AND target.config->>'verify_address' = $3
			   AND target.config->>'verify_server_name' = $10
			   AND identity.status NOT IN ('revoked', 'retired')
			   AND successor.status IN ('active', 'superseded') AND successor.revoked_at IS NULL
			)`, tenantID, in.PQCAssetID, in.VerifyAddress, in.SuccessorFingerprint,
			in.TargetID, in.TargetRevision, in.IdentityID, in.Connector, in.RequiredAgentID,
			in.VerifyServerName).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return ErrUnsafeRollback
		}
		// A known revoked predecessor remains forbidden even under the PQC
		// family. Absence here is expected for a host-adopted certificate; the
		// exact host pin and signed served-state receipt cover that case.
		var state string
		var revoked bool
		err := tx.QueryRow(ctx, `SELECT status, revoked_at IS NOT NULL FROM certificates
			WHERE tenant_id=$1 AND fingerprint=$2 FOR SHARE`, tenantID, in.PredecessorFingerprint).Scan(&state, &revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if revoked || (state != "active" && state != "superseded") {
			return ErrUnsafeRollback
		}
		return nil
	}
	return s.CheckConnectorRollbackTx(ctx, tx, tenantID, in.IdentityID, in.PredecessorFingerprint)
}

// RequeueFailedPQCConnectorRollbackTx is an explicit operator recovery for one
// exact failed host rollback command. The caller has appended a new rollback
// request event from the same run's signed applied receipt. Rechecking the
// current successor and revocation state here prevents an old request from
// making a changed target claimable. ClaimAttempts and signed failed receipts
// remain as history; the next agent claim gets a new attempt number.
func (s *Store) RequeueFailedPQCConnectorRollbackTx(ctx context.Context, tx pgx.Tx,
	tenantID, idempotencyKey string, payload []byte, agentID string) (bool, error) {
	var in struct {
		RunID   string `json:"pqc_run_id"`
		AssetID string `json:"pqc_asset_id"`
	}
	if err := json.Unmarshal(payload, &in); err != nil || in.RunID == "" || in.AssetID == "" ||
		idempotencyKey != "licensed-crypto-migration-host-rollback:"+in.RunID+":"+in.AssetID {
		return false, ErrUnsafeRollback
	}
	if err := s.checkConnectorRollbackPayloadTx(ctx, tx, tenantID, payload); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE outbox
	   SET status='pending', attempts=0, last_error=NULL, next_attempt_at=now(),
	       worker_id=NULL, lease_until=NULL, claimed_by_agent_id=NULL,
	       claim_expires_at=NULL, claim_completed_at=NULL, delivered_at=NULL
	 WHERE tenant_id=$1 AND idempotency_key=$2 AND destination='connector.rollback'
	   AND payload=$3 AND required_agent_role='host' AND required_agent_id=$4::uuid
	   AND status='failed'`, tenantID, idempotencyKey, payload, agentID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
