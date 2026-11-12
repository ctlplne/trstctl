// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// AccessBundleStandingApproval approves, in advance, the privileged session
// requests an access bundle's runs make for one delegated account as one
// role (OD-9): an administrator who may approve access grants it for one
// bundle, account and role until it expires or is revoked. It is never on by
// default. Every session it approved is counted.
type AccessBundleStandingApproval struct {
	TenantID       string
	ID             string
	BundleID       string
	TargetType     string
	TargetID       string
	Role           string
	Reason         string
	GrantedBy      string
	GrantedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	RevokedBy      string
	RevokeReason   string
	Approvals      int64
	LastApprovedAt *time.Time
	EventSequence  uint64
}

// Account is the approval's account and role as the console and the activity
// name them: TYPE/ID as ROLE.
func (a AccessBundleStandingApproval) Account() string {
	return a.TargetType + "/" + a.TargetID + " as " + a.Role
}

// ErrAccessBundleStandingApprovalNotFound reports an approval that is not there.
var ErrAccessBundleStandingApprovalNotFound = errors.New("store: no such access bundle standing approval")

// ApplyAccessBundleStandingApprovalGrantedTx projects
// access.bundle_standing_approval.granted and records it in the bundle's
// activity; a replay converges.
func (s *Store) ApplyAccessBundleStandingApprovalGrantedTx(ctx context.Context, tx pgx.Tx, a AccessBundleStandingApproval, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO access_bundle_standing_approvals
		  (tenant_id, id, bundle_id, target_type, target_id, role, reason, granted_by, granted_at, expires_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		a.TenantID, a.ID, a.BundleID, a.TargetType, a.TargetID, a.Role, a.Reason, a.GrantedBy, a.GrantedAt.UTC(),
		a.ExpiresAt.UTC(), seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, a.TenantID, []string{a.BundleID})
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, a.TenantID, eventID, seq, a.GrantedAt, AccessBundleActivity{
		Action: "standing_approval_granted", BundleIDs: []string{a.BundleID}, BundleNames: names, Actor: a.GrantedBy,
		Detail: a.Account() + " until " + a.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// ApplyAccessBundleStandingApprovalRevokedTx projects
// access.bundle_standing_approval.revoked: the first revocation stands.
func (s *Store) ApplyAccessBundleStandingApprovalRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, by, reason string, at time.Time, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	var a AccessBundleStandingApproval
	err = scanAccessBundleStandingApproval(tx.QueryRow(ctx, `
		UPDATE access_bundle_standing_approvals
		   SET revoked_at = $3, revoked_by = $4, revoke_reason = $5, event_sequence = $6
		 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL AND event_sequence < $6
		RETURNING `+accessBundleStandingApprovalColumns, tenantID, id, at.UTC(), by, reason, seq), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, []string{a.BundleID})
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, at, AccessBundleActivity{
		Action: "standing_approval_revoked", BundleIDs: []string{a.BundleID}, BundleNames: names, Actor: by,
		Detail: a.Account() + ": " + reason,
	})
}

// ApplyAccessBundleStandingApprovalUsedTx counts one session request the
// approval approved (access.bundle_standing_approval.used) and records the
// run that made it in the bundle's activity; replaying the same event counts
// nothing again.
func (s *Store) ApplyAccessBundleStandingApprovalUsedTx(ctx context.Context, tx pgx.Tx, tenantID, id, runID, principal, actor string, at time.Time, eventID string, sequence uint64) error {
	seq, err := accessBundleSequence(sequence)
	if err != nil {
		return err
	}
	var a AccessBundleStandingApproval
	err = scanAccessBundleStandingApproval(tx.QueryRow(ctx, `
		UPDATE access_bundle_standing_approvals
		   SET approvals = approvals + 1, last_approved_at = $3, event_sequence = $4
		 WHERE tenant_id = $1 AND id = $2 AND event_sequence < $4
		RETURNING `+accessBundleStandingApprovalColumns, tenantID, id, at.UTC(), seq), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := accessBundleNamesTx(ctx, tx, tenantID, []string{a.BundleID})
	if err != nil {
		return err
	}
	return insertAccessBundleActivityTx(ctx, tx, tenantID, eventID, seq, at, AccessBundleActivity{
		Action: "standing_approval_used", BundleIDs: []string{a.BundleID}, BundleNames: names, RunID: runID,
		Principal: principal, Actor: actor, Detail: a.Account(),
	})
}

const accessBundleStandingApprovalColumns = `tenant_id::text, id::text, bundle_id::text, target_type, target_id, role, reason,
	granted_by, granted_at, expires_at, revoked_at, revoked_by, revoke_reason, approvals, last_approved_at, event_sequence`

func scanAccessBundleStandingApproval(row pgx.Row, a *AccessBundleStandingApproval) error {
	var seq int64
	if err := row.Scan(&a.TenantID, &a.ID, &a.BundleID, &a.TargetType, &a.TargetID, &a.Role, &a.Reason,
		&a.GrantedBy, &a.GrantedAt, &a.ExpiresAt, &a.RevokedAt, &a.RevokedBy, &a.RevokeReason, &a.Approvals,
		&a.LastApprovedAt, &seq); err != nil {
		return err
	}
	a.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
	return nil
}

// ActiveRunStandingApproval finds the standing approval that approves a
// run's session request for exactly this account and role at now: one that
// is unrevoked and unexpired, on a bundle one of the run's own live grants
// gives, whose bundle still delegates this account and role. A revoked or
// expired run has none.
func (s *Store) ActiveRunStandingApproval(ctx context.Context, tenantID, runID, targetType, targetID, role string, now time.Time) (AccessBundleStandingApproval, bool, error) {
	var out AccessBundleStandingApproval
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		run, err := scanAccessBundleRun(tx.QueryRow(ctx, `SELECT `+accessBundleRunColumns+` FROM access_bundle_runs
			WHERE tenant_id = $1 AND id = $2`, tenantID, runID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if run.RevokedAt != nil || !run.ExpiresAt.After(now) {
			return nil
		}
		err = scanAccessBundleStandingApproval(tx.QueryRow(ctx, `
			SELECT `+accessBundleStandingApprovalColumns+`
			  FROM access_bundle_standing_approvals a
			 WHERE a.tenant_id = $1 AND a.target_type = $5 AND a.target_id = $6 AND a.role = $7
			   AND a.revoked_at IS NULL AND a.expires_at > $3
			   AND EXISTS (
			       SELECT 1 FROM access_bundle_grants g
			         JOIN access_bundles b ON b.tenant_id = g.tenant_id AND b.id = g.bundle_id
			        WHERE g.tenant_id = $1 AND g.principal = $2 AND `+accessBundleLiveGrant+`
			          AND g.id::text = ANY($4::text[]) AND b.id = a.bundle_id
			          AND EXISTS (SELECT 1 FROM jsonb_array_elements(b.access_targets) t
			                       WHERE t->>'target_type' = $5 AND t->>'target_id' = $6 AND t->'roles' ? $7))
			 ORDER BY a.expires_at DESC, a.id
			 LIMIT 1`, tenantID, run.Principal, now.UTC(), run.GrantIDs, targetType, targetID, role), &out)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return AccessBundleStandingApproval{}, false, err
	}
	return out, true, nil
}

// GetAccessBundleStandingApproval reads one approval.
func (s *Store) GetAccessBundleStandingApproval(ctx context.Context, tenantID, id string) (AccessBundleStandingApproval, error) {
	var a AccessBundleStandingApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanAccessBundleStandingApproval(tx.QueryRow(ctx, `SELECT `+accessBundleStandingApprovalColumns+`
			  FROM access_bundle_standing_approvals WHERE tenant_id = $1 AND id = $2`, tenantID, id), &a)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessBundleStandingApproval{}, ErrAccessBundleStandingApprovalNotFound
	}
	return a, err
}

// ListAccessBundleStandingApprovals lists a bundle's approvals, newest
// first, at most 200.
func (s *Store) ListAccessBundleStandingApprovals(ctx context.Context, tenantID, bundleID string) ([]AccessBundleStandingApproval, error) {
	var out []AccessBundleStandingApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+accessBundleStandingApprovalColumns+`
			  FROM access_bundle_standing_approvals WHERE tenant_id = $1 AND bundle_id = $2
			 ORDER BY granted_at DESC, id LIMIT 200`, tenantID, bundleID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AccessBundleStandingApproval
			if err := scanAccessBundleStandingApproval(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// ListLivePAMSessionsApprovedBy lists the active privileged sessions whose
// request the given approver approved (for a standing approval,
// "standing-approval:<id>"), oldest first, at most limit (1 to 100).
func (s *Store) ListLivePAMSessionsApprovedBy(ctx context.Context, tenantID, approver string, limit int) ([]PAMSession, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []PAMSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, target_type, target_id, role, status,
			        subject, requested_by, reason, attestation_id, backend_ref, ssh_key_id,
			        ssh_serial, idempotency_key, audit, attestation, started_at, expires_at, ended_at,
			        revocation_requested_by, revocation_reason, revocation_requested_at,
			        revocation_idempotency_key, revocation_failure, revocation_failed_at,
			        delivery, COALESCE(gateway_agent_id::text, ''), gateway_ticket_digest, ssh_principal,
			        gateway_ended_at, gateway_ended, command_policy, COALESCE(approval_request_id::text, ''), web_sign_in
			   FROM pam_sessions s
			  WHERE s.tenant_id = $1 AND s.status = 'active' AND s.approval_request_id::text <> ''
			    AND EXISTS (SELECT 1 FROM operation_approval_decisions d
			                 WHERE d.tenant_id = s.tenant_id AND d.request_id::text = s.approval_request_id::text
			                   AND d.approver = $2 AND d.decision = $3)
			  ORDER BY s.started_at, s.id
			  LIMIT $4`,
			tenantID, approver, ApprovalDecisionApprove, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PAMSession
			if err := scanPAMSession(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
