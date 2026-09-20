// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ProfileEditApprovalDecision is one reviewer's recorded decision on a parked
// profile create/edit.
type ProfileEditApprovalDecision struct {
	Approver string    `json:"approver"`
	Decision string    `json:"decision"`
	At       time.Time `json:"at"`
}

// ProfileEditApproval is the projected row of a parked profile create/edit
// under dual control: the queued spec and who may still approve it. It is
// event-sourced from profile.edit_approval.requested / .approved and closed by
// the profile.created/updated event that carries its id (OPP-R09).
type ProfileEditApproval struct {
	TenantID              string
	ID                    string
	Name                  string
	Spec                  json.RawMessage
	Requester             string
	RequiredApprovals     int
	Approvals             []ProfileEditApprovalDecision
	State                 string
	ProfileID             string
	RestoredFromVersion   int
	RestoreReason         string
	ExpectedActiveVersion int
	CreatedAt             time.Time
	ExpiresAt             time.Time
	UpdatedAt             time.Time
}

// ErrProfileEditApprovalNotFound is returned for an unknown parked request.
var ErrProfileEditApprovalNotFound = errors.New("store: profile edit approval request not found")

const profileEditApprovalColumns = `tenant_id::text, id::text, name, spec, requester, required_approvals, approvals, state, profile_id,
	restored_from_version, restore_reason, expected_active_version, created_at, expires_at, updated_at`

func scanProfileEditApproval(row pgx.Row) (ProfileEditApproval, error) {
	var r ProfileEditApproval
	var approvals []byte
	if err := row.Scan(&r.TenantID, &r.ID, &r.Name, &r.Spec, &r.Requester, &r.RequiredApprovals, &approvals, &r.State, &r.ProfileID,
		&r.RestoredFromVersion, &r.RestoreReason, &r.ExpectedActiveVersion, &r.CreatedAt, &r.ExpiresAt, &r.UpdatedAt); err != nil {
		return ProfileEditApproval{}, err
	}
	if len(approvals) > 0 {
		if err := json.Unmarshal(approvals, &r.Approvals); err != nil {
			return ProfileEditApproval{}, fmt.Errorf("store: decode profile edit approvals: %w", err)
		}
	}
	return r, nil
}

// ApplyProfileEditApprovalRequestedTx projects profile.edit_approval.requested:
// the parked request exists once, whichever of the inline apply and the durable
// tail applies it first (the primary key is the arbiter; a replay is a no-op).
func (s *Store) ApplyProfileEditApprovalRequestedTx(ctx context.Context, tx pgx.Tx, r ProfileEditApproval) error {
	approvals, err := json.Marshal(r.Approvals)
	if err != nil {
		return err
	}
	if r.Approvals == nil {
		approvals = []byte("[]")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO profile_edit_approvals
		        (tenant_id, id, name, spec, requester, required_approvals, approvals, state, profile_id,
		         restored_from_version, restore_reason, expected_active_version, created_at, expires_at, updated_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7::jsonb, 'awaiting_approval', '', $8, $9, $10, $11, $12, $11)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		r.TenantID, r.ID, r.Name, jsonbOrEmpty(r.Spec), r.Requester, r.RequiredApprovals, approvals,
		r.RestoredFromVersion, r.RestoreReason, r.ExpectedActiveVersion, r.CreatedAt.UTC(), r.ExpiresAt.UTC())
	return err
}

// ApplyProfileEditApprovalApprovedTx projects profile.edit_approval.approved:
// the approver's decision is appended once (an identical replay is absorbed by
// the containment check) and the request moves to approved while it is still
// awaiting approval. A request already issued keeps its terminal state.
func (s *Store) ApplyProfileEditApprovalApprovedTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, approver string, at time.Time) error {
	decision, err := json.Marshal([]ProfileEditApprovalDecision{{Approver: approver, Decision: "approve", At: at.UTC()}})
	if err != nil {
		return err
	}
	probe, err := json.Marshal([]map[string]string{{"approver": approver, "decision": "approve"}})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE profile_edit_approvals
		   SET approvals = CASE WHEN approvals @> $4::jsonb THEN approvals ELSE approvals || $3::jsonb END,
		       state = CASE WHEN state = 'awaiting_approval' THEN 'approved' ELSE state END,
		       updated_at = GREATEST(updated_at, $5)
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID, requestID, decision, probe, at.UTC())
	return err
}

// ApplyProfileEditApprovalIssuedTx projects the profile version event that
// closes a parked request: the request is issued and names the version it
// produced. Idempotent under replay.
func (s *Store) ApplyProfileEditApprovalIssuedTx(ctx context.Context, tx pgx.Tx, tenantID, requestID, profileID string, at time.Time) error {
	_, err := tx.Exec(ctx, `
		UPDATE profile_edit_approvals
		   SET state = 'issued', profile_id = $3, updated_at = GREATEST(updated_at, $4)
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID, requestID, profileID, at.UTC())
	return err
}

// GetProfileEditApproval loads one parked request of the tenant.
func (s *Store) GetProfileEditApproval(ctx context.Context, tenantID, requestID string) (ProfileEditApproval, error) {
	var out ProfileEditApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanProfileEditApproval(tx.QueryRow(ctx,
			`SELECT `+profileEditApprovalColumns+` FROM profile_edit_approvals WHERE tenant_id = $1 AND id = $2`, tenantID, requestID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProfileEditApprovalNotFound
		}
		return err
	})
	return out, err
}

// ListProfileEditApprovals lists the tenant's parked requests, oldest first.
func (s *Store) ListProfileEditApprovals(ctx context.Context, tenantID string) ([]ProfileEditApproval, error) {
	out := make([]ProfileEditApproval, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+profileEditApprovalColumns+` FROM profile_edit_approvals WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanProfileEditApproval(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
