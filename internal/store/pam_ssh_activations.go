// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PAMSSHActivation is a metadata-only projection of an approved SSH signing
// attempt. The certificate and subject public key never enter this table.
type PAMSSHActivation struct {
	TenantID    string
	SessionID   string
	RequestID   string
	KeyID       string
	Status      string
	RequestedAt time.Time
}

func (s *Store) ApplyPAMSSHActivationRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, requestID string, at time.Time) error {
	keyID := "pam:" + sessionID
	_, err := tx.Exec(ctx, `INSERT INTO pam_ssh_activations
		(tenant_id, session_id, request_id, key_id, status, requested_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'pending', $5)
		ON CONFLICT (tenant_id, session_id) DO NOTHING`, tenantID, sessionID, requestID, keyID, at)
	if err != nil {
		return err
	}
	var canonicalRequest, canonicalKeyID string
	if err := tx.QueryRow(ctx, `SELECT request_id::text, key_id FROM pam_ssh_activations
		WHERE tenant_id=$1::uuid AND session_id=$2::uuid`, tenantID, sessionID).Scan(&canonicalRequest, &canonicalKeyID); err != nil {
		return err
	}
	if canonicalRequest != requestID || canonicalKeyID != keyID {
		return errors.New("store: PAM SSH activation collides with a different approved request")
	}
	return nil
}

func (s *Store) ApplyPAMSSHActivationCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, at time.Time) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM pam_ssh_activations
		WHERE tenant_id=$1::uuid AND session_id=$2::uuid`, tenantID, sessionID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical SSH sessions predate the recoverable intent row.
	}
	if err != nil {
		return err
	}
	if status != "pending" && status != "completed" {
		return errors.New("store: recovered SSH activation cannot start a session")
	}
	_, err = tx.Exec(ctx, `UPDATE pam_ssh_activations
		SET status='completed', completed_at=coalesce(completed_at,$3)
		WHERE tenant_id=$1::uuid AND session_id=$2::uuid AND status IN ('pending','completed')`, tenantID, sessionID, at)
	return err
}

func (s *Store) ApplyPAMSSHActivationRecoveryRequestedTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, keyID string, at time.Time) error {
	if keyID != "pam:"+sessionID {
		return errors.New("store: SSH recovery key ID disagrees with session")
	}
	result, err := tx.Exec(ctx, `UPDATE pam_ssh_activations
		SET status='revoking', revocation_requested_at=coalesce(revocation_requested_at,$4)
		WHERE tenant_id=$1::uuid AND session_id=$2::uuid AND key_id=$3 AND status IN ('pending','revoking')`,
		tenantID, sessionID, keyID, at)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("store: SSH recovery request has no pending signing intent")
	}
	return nil
}

func (s *Store) ApplyPAMSSHActivationRecoveredTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, keyID string, at time.Time) error {
	if keyID != "pam:"+sessionID {
		return errors.New("store: recovered SSH key ID disagrees with session")
	}
	result, err := tx.Exec(ctx, `UPDATE pam_ssh_activations
		SET status='recovered', recovered_at=coalesce(recovered_at,$4)
		WHERE tenant_id=$1::uuid AND session_id=$2::uuid AND key_id=$3 AND status IN ('revoking','recovered')`,
		tenantID, sessionID, keyID, at)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("store: SSH recovery completion has no revoking signing intent")
	}
	return nil
}

func (s *Store) GetPAMSSHActivation(ctx context.Context, tenantID, sessionID string) (PAMSSHActivation, error) {
	var out PAMSSHActivation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id::text, session_id::text, request_id::text,
			key_id, status, requested_at FROM pam_ssh_activations
			WHERE tenant_id=$1::uuid AND session_id=$2::uuid`, tenantID, sessionID).Scan(
			&out.TenantID, &out.SessionID, &out.RequestID, &out.KeyID, &out.Status, &out.RequestedAt)
	})
	return out, err
}

// ListPendingPAMSSHActivations is a metadata-only cross-tenant worker scan.
// The worker takes the exact tenant/session advisory fence and re-reads each row
// under RLS before it appends a compensating event.
func (s *Store) ListPendingPAMSSHActivations(ctx context.Context, limit int) ([]PAMSSHActivation, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — crash recovery scans pending SSH metadata across tenants; each follow-up read and event is tenant-scoped.
		`SELECT tenant_id::text, session_id::text, request_id::text, key_id, status, requested_at
		 FROM pam_ssh_activations WHERE status IN ('pending','revoking')
		 ORDER BY requested_at, tenant_id, session_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PAMSSHActivation, 0)
	for rows.Next() {
		var item PAMSSHActivation
		if err := rows.Scan(&item.TenantID, &item.SessionID, &item.RequestID,
			&item.KeyID, &item.Status, &item.RequestedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// WithPAMSSHActivationFence serializes one signing attempt and its crash
// recovery across replicas. PostgreSQL releases this session lock when a process
// dies; it never holds a read-model transaction open during signer I/O.
func (s *Store) WithPAMSSHActivationFence(ctx context.Context, tenantID, sessionID string, fn func() error) (acquired bool, err error) {
	if _, parseErr := uuid.Parse(tenantID); parseErr != nil {
		return false, errors.New("store: PAM activation tenant must be a UUID")
	}
	if _, parseErr := uuid.Parse(sessionID); parseErr != nil || fn == nil {
		return false, errors.New("store: PAM activation session and callback are required")
	}
	conn, err := s.lockSessionPool(ctx).Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	name := "pam-ssh-activation\x1f" + tenantID + "\x1f" + sessionID
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, name).Scan(&acquired); err != nil {
		return false, fmt.Errorf("store: acquire PAM SSH activation fence: %w", err)
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		unlockErr := conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, name).Scan(&unlocked)
		if unlockErr != nil || !unlocked {
			_ = conn.Conn().Close(context.Background())
			if unlockErr == nil {
				unlockErr = errors.New("store: PAM SSH activation fence was not held on release")
			}
			err = errors.Join(err, unlockErr)
		}
	}()
	err = fn()
	return true, err
}
