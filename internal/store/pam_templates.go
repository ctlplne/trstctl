// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMTemplateNotFound is a template that does not exist or was deleted.
var ErrPAMTemplateNotFound = errors.New("store: PAM access template not found")

// ErrPAMEmergencyGrantNotFound is an emergency grant that does not exist.
var ErrPAMEmergencyGrantNotFound = errors.New("store: PAM emergency grant not found")

// PAMAccessTemplate is a reusable access template (A258): the reason a
// session request records, the approvals it needs and its maximum length.
type PAMAccessTemplate struct {
	ID, Name, Reason  string
	RequiredApprovals int
	MaxTTLSeconds     int
	Revision          int64
	SavedBy           string
	SavedAt           time.Time
	DeletedAt         *time.Time
}

// PAMEmergencyGrant is a session a named responder opened without waiting
// for approval, with its post-incident review (A258).
type PAMEmergencyGrant struct {
	// TenantID is set only by the cross-tenant notice reconciler's list.
	TenantID                     string
	SessionID, Responder, Reason string
	TargetType, TargetID, Role   string
	OpenedAt, ExpiresAt          time.Time
	ReviewStatus                 string
	Reviewer, Outcome, Notes     string
	ReviewedAt                   *time.Time
}

const pamTemplateColumns = `id::text, name, reason, required_approvals, max_ttl_seconds, revision, saved_by, saved_at, deleted_at`

func scanPAMTemplate(row pgx.Row) (PAMAccessTemplate, error) {
	var t PAMAccessTemplate
	err := row.Scan(&t.ID, &t.Name, &t.Reason, &t.RequiredApprovals, &t.MaxTTLSeconds, &t.Revision, &t.SavedBy, &t.SavedAt, &t.DeletedAt)
	return t, err
}

// ApplyPAMTemplateSavedTx projects pam.template.saved: a template at its
// revision. An older revision changes nothing, and a deleted template is not
// brought back.
func (s *Store) ApplyPAMTemplateSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, t PAMAccessTemplate) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO pam_access_templates AS cur (tenant_id, id, name, reason, required_approvals, max_ttl_seconds, revision, saved_by, saved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
		    name = EXCLUDED.name, reason = EXCLUDED.reason, required_approvals = EXCLUDED.required_approvals,
		    max_ttl_seconds = EXCLUDED.max_ttl_seconds, revision = EXCLUDED.revision,
		    saved_by = EXCLUDED.saved_by, saved_at = EXCLUDED.saved_at
		  WHERE cur.revision < EXCLUDED.revision AND cur.deleted_at IS NULL`,
		tenantID, t.ID, t.Name, t.Reason, t.RequiredApprovals, t.MaxTTLSeconds, t.Revision, t.SavedBy, t.SavedAt.UTC())
	return err
}

// ApplyPAMTemplateDeletedTx projects pam.template.deleted.
func (s *Store) ApplyPAMTemplateDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_access_templates SET deleted_at = $3
		WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, id, at.UTC())
	return err
}

// GetPAMTemplate returns a live template.
func (s *Store) GetPAMTemplate(ctx context.Context, tenantID, id string) (PAMAccessTemplate, error) {
	var t PAMAccessTemplate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		t, err = scanPAMTemplate(tx.QueryRow(ctx, `SELECT `+pamTemplateColumns+` FROM pam_access_templates
			WHERE tenant_id = $1 AND id::text = $2 AND deleted_at IS NULL`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMAccessTemplate{}, ErrPAMTemplateNotFound
	}
	return t, err
}

// ListPAMTemplates returns a tenant's live templates by name.
func (s *Store) ListPAMTemplates(ctx context.Context, tenantID string) ([]PAMAccessTemplate, error) {
	out := []PAMAccessTemplate{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamTemplateColumns+` FROM pam_access_templates
			WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY lower(name), id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanPAMTemplate(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyPAMEmergencyRespondersSetTx projects pam.emergency.responders_set: the
// tenant's whole responder list.
func (s *Store) ApplyPAMEmergencyRespondersSetTx(ctx context.Context, tx pgx.Tx, tenantID string, subjects []string, by string, at time.Time) error {
	if _, err := tx.Exec(ctx, `DELETE FROM pam_emergency_responders WHERE tenant_id = $1`, tenantID); err != nil {
		return err
	}
	for _, subject := range subjects {
		if _, err := tx.Exec(ctx, `INSERT INTO pam_emergency_responders (tenant_id, subject, set_by, set_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, subject) DO NOTHING`, tenantID, subject, by, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// ListPAMEmergencyResponders returns a tenant's named responders.
func (s *Store) ListPAMEmergencyResponders(ctx context.Context, tenantID string) ([]string, error) {
	out := []string{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT subject FROM pam_emergency_responders WHERE tenant_id = $1 ORDER BY subject`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var subject string
			if err := rows.Scan(&subject); err != nil {
				return err
			}
			out = append(out, subject)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyPAMEmergencyOpenedTx projects pam.emergency.opened.
func (s *Store) ApplyPAMEmergencyOpenedTx(ctx context.Context, tx pgx.Tx, tenantID string, g PAMEmergencyGrant) error {
	_, err := tx.Exec(ctx, `INSERT INTO pam_emergency_grants
		(tenant_id, session_id, responder, reason, target_type, target_id, role, opened_at, expires_at, review_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
		ON CONFLICT (tenant_id, session_id) DO NOTHING`,
		tenantID, g.SessionID, g.Responder, g.Reason, g.TargetType, g.TargetID, g.Role, g.OpenedAt.UTC(), g.ExpiresAt.UTC())
	return err
}

// ApplyPAMEmergencyReviewedTx projects pam.emergency.reviewed: the first
// review closes the grant's review.
func (s *Store) ApplyPAMEmergencyReviewedTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reviewer, outcome, notes string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_emergency_grants
		SET review_status = 'reviewed', reviewer = $3, review_outcome = $4, review_notes = $5, reviewed_at = $6
		WHERE tenant_id = $1 AND session_id = $2 AND review_status = 'pending'`,
		tenantID, sessionID, reviewer, outcome, notes, at.UTC())
	return err
}

const pamEmergencyColumns = `session_id::text, responder, reason, target_type, target_id, role, opened_at, expires_at,
	review_status, reviewer, review_outcome, review_notes, reviewed_at`

func scanPAMEmergencyGrant(row pgx.Row) (PAMEmergencyGrant, error) {
	var g PAMEmergencyGrant
	err := row.Scan(&g.SessionID, &g.Responder, &g.Reason, &g.TargetType, &g.TargetID, &g.Role, &g.OpenedAt, &g.ExpiresAt,
		&g.ReviewStatus, &g.Reviewer, &g.Outcome, &g.Notes, &g.ReviewedAt)
	return g, err
}

// GetPAMEmergencyGrant returns one emergency grant.
func (s *Store) GetPAMEmergencyGrant(ctx context.Context, tenantID, sessionID string) (PAMEmergencyGrant, error) {
	var g PAMEmergencyGrant
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		g, err = scanPAMEmergencyGrant(tx.QueryRow(ctx, `SELECT `+pamEmergencyColumns+` FROM pam_emergency_grants
			WHERE tenant_id = $1 AND session_id::text = $2`, tenantID, sessionID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMEmergencyGrant{}, ErrPAMEmergencyGrantNotFound
	}
	return g, err
}

// ListPAMEmergencyGrants returns a tenant's emergency grants, newest first.
func (s *Store) ListPAMEmergencyGrants(ctx context.Context, tenantID string, limit int) ([]PAMEmergencyGrant, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	out := []PAMEmergencyGrant{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamEmergencyColumns+` FROM pam_emergency_grants
			WHERE tenant_id = $1 ORDER BY opened_at DESC, session_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanPAMEmergencyGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

// ListRecentPAMEmergencyGrants lists every tenant's grants opened since, for
// the notice reconciler (A258).
func (s *Store) ListRecentPAMEmergencyGrants(ctx context.Context, since time.Time, limit int) ([]PAMEmergencyGrant, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — the PAM emergency notice reconciler re-queues, per tenant, the approval-channel notice of each recent emergency grant whose notice a crash left out; each enqueue runs under its own tenant's RLS context.
		`SELECT tenant_id::text, `+pamEmergencyColumns+` FROM pam_emergency_grants
		  WHERE opened_at >= $1 ORDER BY opened_at, tenant_id, session_id LIMIT $2`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMEmergencyGrant
	for rows.Next() {
		var g PAMEmergencyGrant
		if err := rows.Scan(&g.TenantID, &g.SessionID, &g.Responder, &g.Reason, &g.TargetType, &g.TargetID, &g.Role, &g.OpenedAt,
			&g.ExpiresAt, &g.ReviewStatus, &g.Reviewer, &g.Outcome, &g.Notes, &g.ReviewedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
