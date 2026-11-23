// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type recoveryPairProofOperationContextKey struct{}

// WithRecoveryPairProofOperation binds an atomic replay to its preverified
// operation. Only a matching owner-transaction proof row can authorize a
// v1-different receipt; this context value alone grants nothing.
func WithRecoveryPairProofOperation(ctx context.Context, operationID string) (context.Context, error) {
	if _, err := uuid.Parse(operationID); err != nil {
		return nil, ErrRecoveryPairProofMismatch
	}
	return context.WithValue(ctx, recoveryPairProofOperationContextKey{}, operationID), nil
}

func recoveryPairProofOperation(ctx context.Context) (string, bool) {
	operationID, ok := ctx.Value(recoveryPairProofOperationContextKey{}).(string)
	return operationID, ok
}

var ErrRecoveryPairProofMismatch = errors.New("store: authenticated recovery pair proof is missing or changed")

// RecoveryPairProof contains hashes of the exact ciphertext copies and key
// state authenticated before a destructive rebuild. It carries no plaintext.
// The table is owner-writable only and is consumed in the rebuild transaction.
type RecoveryPairProof struct {
	TenantID       string
	OperationID    string
	EventID        string
	PairKind       string
	RowID          string
	EventSHA256    string
	RowSHA256      string
	KeyStateSHA256 string
}

func (p RecoveryPairProof) valid() bool {
	if _, err := uuid.Parse(p.TenantID); err != nil {
		return false
	}
	if _, err := uuid.Parse(p.OperationID); err != nil {
		return false
	}
	if p.EventID == "" || p.RowID == "" ||
		p.PairKind != "mutation_receipt" && p.PairKind != "sync_outbox" &&
			p.PairKind != "recover_source" && p.PairKind != "undelete_tombstone" &&
			p.PairKind != "restore_outbox" {
		return false
	}
	for _, digest := range []string{p.EventSHA256, p.RowSHA256, p.KeyStateSHA256} {
		if len(digest) != 64 {
			return false
		}
		for _, ch := range digest {
			if ch < '0' || ch > '9' && ch < 'a' || ch > 'f' {
				return false
			}
		}
	}
	return true
}

func (s *Store) InsertRecoveryPairProofTx(ctx context.Context, tx pgx.Tx, proof RecoveryPairProof) error {
	if s == nil || tx == nil || !proof.valid() {
		return ErrRecoveryPairProofMismatch
	}
	tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.recovery_pair_proofs
		(tenant_id,operation_id,event_id,pair_kind,row_id,event_sha256,row_sha256,key_state_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id,operation_id,event_id,pair_kind,row_id) DO UPDATE
		SET event_sha256=EXCLUDED.event_sha256
		WHERE trstctl_recovery.recovery_pair_proofs.event_sha256=EXCLUDED.event_sha256
		  AND trstctl_recovery.recovery_pair_proofs.row_sha256=EXCLUDED.row_sha256
		  AND trstctl_recovery.recovery_pair_proofs.key_state_sha256=EXCLUDED.key_state_sha256`,
		proof.TenantID, proof.OperationID, proof.EventID, proof.PairKind, proof.RowID,
		proof.EventSHA256, proof.RowSHA256, proof.KeyStateSHA256)
	if err != nil {
		return fmt.Errorf("store: insert recovery pair proof: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRecoveryPairProofMismatch
	}
	return nil
}

// ConsumeRecoveryPairProofTx deletes exactly the row whose previously verified
// event bytes, independent row bytes and key state are still current. A second
// consume or any changed hash fails closed.
func (s *Store) ConsumeRecoveryPairProofTx(ctx context.Context, tx pgx.Tx, proof RecoveryPairProof) error {
	if s == nil || tx == nil || !proof.valid() {
		return ErrRecoveryPairProofMismatch
	}
	tag, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.recovery_pair_proofs
		WHERE tenant_id=$1 AND operation_id=$2 AND event_id=$3 AND pair_kind=$4 AND row_id=$5
		  AND event_sha256=$6 AND row_sha256=$7 AND key_state_sha256=$8`,
		proof.TenantID, proof.OperationID, proof.EventID, proof.PairKind, proof.RowID,
		proof.EventSHA256, proof.RowSHA256, proof.KeyStateSHA256)
	if err != nil {
		return fmt.Errorf("store: consume recovery pair proof: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrRecoveryPairProofMismatch
	}
	return nil
}

// AssertNoRecoveryPairProofsTx is the final atomic-rebuild gate. A staged pair
// that replay never consumed means the source/receiver graph changed or was
// skipped, so committing the rebuilt model would be lossy.
func (s *Store) AssertNoRecoveryPairProofsTx(ctx context.Context, tx pgx.Tx, operationID string) error {
	if s == nil || tx == nil {
		return ErrRecoveryPairProofMismatch
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return ErrRecoveryPairProofMismatch
	}
	var unconsumed bool
	//trstctl:system-query — cross-tenant system atomic rebuild tests whether its exact operation left any tenant_id proof unconsumed; it returns one boolean and no tenant or ciphertext data.
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.recovery_pair_proofs
		WHERE operation_id=$1)`, operationID).Scan(&unconsumed); err != nil {
		return err
	}
	if unconsumed {
		return ErrRecoveryPairProofMismatch
	}
	return nil
}
