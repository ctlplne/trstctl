// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// PAM session approval link states (G1-L6).
const (
	// PAMApprovalLinkRecorded: the started event names the approval, or was
	// written by code that records the link, so none named means none was
	// consumed.
	PAMApprovalLinkRecorded = "recorded"
	// PAMApprovalLinkDerived: the started event predates the link; the
	// activation's own event named the approval it consumed.
	PAMApprovalLinkDerived = "derived"
)

// ApplyPAMSessionApprovalLinkTx records the approval a session's activation
// consumed, once: replaying the activation is a no-op, and a different
// approval for the same session is refused.
func (s *Store) ApplyPAMSessionApprovalLinkTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, approvalRequestID string, at time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO pam_session_approval_links (tenant_id, session_id, approval_request_id, activated_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4)
		ON CONFLICT (tenant_id, session_id) DO NOTHING`, tenantID, sessionID, approvalRequestID, at); err != nil {
		return err
	}
	held, _, err := s.PAMSessionApprovalLinkTx(ctx, tx, tenantID, sessionID)
	if err != nil {
		return err
	}
	if held != approvalRequestID {
		return errors.New("store: PAM session activation names a different approval than the one recorded")
	}
	return nil
}

// PAMSessionApprovalLinkTx is the approval a session's activation consumed,
// if its activation was recorded.
func (s *Store) PAMSessionApprovalLinkTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (string, bool, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT approval_request_id::text FROM pam_session_approval_links
		WHERE tenant_id = $1::uuid AND session_id = $2::uuid`, tenantID, sessionID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}
