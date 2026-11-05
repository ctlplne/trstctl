// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMAutoApprovalRuleNotFound is a rule that does not exist (or was deleted).
var ErrPAMAutoApprovalRuleNotFound = errors.New("store: PAM auto-approval rule not found")

// PAMAutoApprovalRule approves the privileged access requests that match every
// condition it sets (A261 part 3). Empty lists and an empty window or ticket
// pattern set no condition; a rule always names a target scope.
type PAMAutoApprovalRule struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	AppliesTo      []string   `json:"applies_to"`
	TargetTypes    []string   `json:"target_types"`
	TargetIDs      []string   `json:"target_ids"`
	Folders        []string   `json:"folders"`
	RequesterRoles []string   `json:"requester_roles"`
	WindowDays     []string   `json:"window_days"`
	WindowStart    string     `json:"window_start"`
	WindowEnd      string     `json:"window_end"`
	TimeZone       string     `json:"time_zone"`
	TicketPattern  string     `json:"ticket_pattern"`
	MaxTTLSeconds  int        `json:"max_ttl_seconds"`
	Enabled        bool       `json:"enabled"`
	Revision       int64      `json:"revision"`
	SavedBy        string     `json:"saved_by"`
	SavedAt        time.Time  `json:"saved_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

const pamAutoApprovalRuleColumns = `id::text, name, applies_to, target_types, target_ids, folders, requester_roles, window_days,
    window_start, window_end, time_zone, ticket_pattern, max_ttl_seconds, enabled, revision, saved_by, saved_at, deleted_at`

func scanPAMAutoApprovalRule(row pgx.Row) (PAMAutoApprovalRule, error) {
	var r PAMAutoApprovalRule
	err := row.Scan(&r.ID, &r.Name, &r.AppliesTo, &r.TargetTypes, &r.TargetIDs, &r.Folders, &r.RequesterRoles, &r.WindowDays,
		&r.WindowStart, &r.WindowEnd, &r.TimeZone, &r.TicketPattern, &r.MaxTTLSeconds, &r.Enabled, &r.Revision, &r.SavedBy, &r.SavedAt,
		&r.DeletedAt)
	return r, err
}

func pamRuleList(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// ApplyPAMAutoApprovalRuleSavedTx projects pam.auto_approval_rule.saved: a rule
// at its revision. An older revision changes nothing, and a deleted rule is not
// brought back.
func (s *Store) ApplyPAMAutoApprovalRuleSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, r PAMAutoApprovalRule) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO pam_auto_approval_rules AS cur (tenant_id, id, name, applies_to, target_types, target_ids, folders, requester_roles,
		    window_days, window_start, window_end, time_zone, ticket_pattern, max_ttl_seconds, enabled, revision, saved_by, saved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (tenant_id, id) DO UPDATE SET
		    name = EXCLUDED.name, applies_to = EXCLUDED.applies_to, target_types = EXCLUDED.target_types,
		    target_ids = EXCLUDED.target_ids, folders = EXCLUDED.folders, requester_roles = EXCLUDED.requester_roles,
		    window_days = EXCLUDED.window_days, window_start = EXCLUDED.window_start, window_end = EXCLUDED.window_end,
		    time_zone = EXCLUDED.time_zone, ticket_pattern = EXCLUDED.ticket_pattern, max_ttl_seconds = EXCLUDED.max_ttl_seconds,
		    enabled = EXCLUDED.enabled, revision = EXCLUDED.revision, saved_by = EXCLUDED.saved_by, saved_at = EXCLUDED.saved_at
		  WHERE cur.revision < EXCLUDED.revision AND cur.deleted_at IS NULL`,
		tenantID, r.ID, r.Name, pamRuleList(r.AppliesTo), pamRuleList(r.TargetTypes), pamRuleList(r.TargetIDs), pamRuleList(r.Folders), pamRuleList(r.RequesterRoles),
		pamRuleList(r.WindowDays), r.WindowStart, r.WindowEnd, r.TimeZone, r.TicketPattern, r.MaxTTLSeconds, r.Enabled, r.Revision, r.SavedBy,
		r.SavedAt.UTC())
	return err
}

// ApplyPAMAutoApprovalRuleDeletedTx projects pam.auto_approval_rule.deleted.
func (s *Store) ApplyPAMAutoApprovalRuleDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, revision int64, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_auto_approval_rules SET deleted_at = $4, revision = $3
		WHERE tenant_id = $1 AND id = $2 AND revision < $3`, tenantID, id, revision, at.UTC())
	return err
}

// GetPAMAutoApprovalRule returns a live rule.
func (s *Store) GetPAMAutoApprovalRule(ctx context.Context, tenantID, id string) (PAMAutoApprovalRule, error) {
	var r PAMAutoApprovalRule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = scanPAMAutoApprovalRule(tx.QueryRow(ctx, `SELECT `+pamAutoApprovalRuleColumns+` FROM pam_auto_approval_rules
			WHERE tenant_id = $1 AND id::text = $2 AND deleted_at IS NULL`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMAutoApprovalRule{}, ErrPAMAutoApprovalRuleNotFound
	}
	return r, err
}

// ListPAMAutoApprovalRules returns a tenant's live rules in the order they are
// tried: by ID.
func (s *Store) ListPAMAutoApprovalRules(ctx context.Context, tenantID string) ([]PAMAutoApprovalRule, error) {
	out := []PAMAutoApprovalRule{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamAutoApprovalRuleColumns+` FROM pam_auto_approval_rules
			WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 257`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPAMAutoApprovalRule(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetPAMAutoApprovalRuleAnyState also reads a tombstone so callers cannot
// recreate a deleted rule ID or reset its revision.
func (s *Store) GetPAMAutoApprovalRuleAnyState(ctx context.Context, tenantID, id string) (PAMAutoApprovalRule, error) {
	var r PAMAutoApprovalRule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		r, err = scanPAMAutoApprovalRule(tx.QueryRow(ctx, `SELECT `+pamAutoApprovalRuleColumns+` FROM pam_auto_approval_rules WHERE tenant_id = $1 AND id::text = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMAutoApprovalRule{}, ErrPAMAutoApprovalRuleNotFound
	}
	return r, err
}
