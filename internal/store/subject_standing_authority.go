// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// SubjectStandingAuthority is what a subject may still authorize outside any
// one request, from the records the control plane keeps (CR-001): the roles
// of its member record and the scopes of its own live API tokens. A sign-in's
// identity-provider roles are not recorded, so they are not here.
type SubjectStandingAuthority struct {
	// MemberRoles are an active member's roles, as the member record names
	// them now. They are empty while the member is offboarded or a member
	// command for the subject is still pending, as a browser session then
	// gets no roles either.
	MemberRoles []string
	// TokenScopes are the distinct scopes of the subject's live API tokens:
	// not revoked or being revoked, not expired at the given time, and not
	// minted for the subject by someone else (F262). A subject that is
	// offboarded or being offboarded has none, as no token of it then
	// authenticates.
	TokenScopes []string
}

// GetSubjectStandingAuthority reads a subject's standing authority in its
// tenant (RLS-enforced). The token liveness conditions are the ones
// LookupAPITokenByHash applies when a token authenticates.
func (s *Store) GetSubjectStandingAuthority(ctx context.Context, tenantID, subject string, at time.Time) (SubjectStandingAuthority, error) {
	var out SubjectStandingAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ref := privacy.SubjectRef(tenantID, subject)
		if err := tx.QueryRow(ctx, `SELECT COALESCE(m.roles, '{}'::text[])
		 FROM (SELECT 1) AS seed
		 LEFT JOIN LATERAL (SELECT roles FROM tenant_members
		                    WHERE tenant_id = $1 AND subject = $2 AND status = 'active'
		                      AND NOT EXISTS (SELECT 1 FROM tenant_member_upsert_commands AS c
		                                      WHERE c.tenant_id = $1 AND c.subject_ref = $3 AND c.status = 'pending')
		                      AND NOT EXISTS (SELECT 1 FROM tenant_member_offboard_commands AS c
		                                      WHERE c.tenant_id = $1 AND c.subject_ref = $3 AND c.status = 'pending')) AS m ON true`,
			tenantID, subject, ref).Scan(&out.MemberRoles); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT scope
		 FROM api_tokens AS t CROSS JOIN LATERAL unnest(t.scopes) AS scope
		 WHERE t.tenant_id = $1 AND t.subject = $2 AND t.revoked_at IS NULL
		   AND NOT COALESCE(t.delegated, false)
		   AND (t.expires_at IS NULL OR t.expires_at > $3)
		   AND NOT EXISTS (SELECT 1 FROM api_token_revocation_commands AS c
		                   WHERE c.tenant_id = t.tenant_id AND c.token_id = t.id)
		   AND NOT EXISTS (SELECT 1 FROM tenant_member_offboard_commands AS c
		                   LEFT JOIN tenant_members AS m ON m.tenant_id = c.tenant_id AND m.subject_ref = c.subject_ref
		                   WHERE c.tenant_id = t.tenant_id AND c.subject_ref = t.subject_ref
		                     AND (c.status = 'pending' OR m.status IS DISTINCT FROM 'active'))
		   AND NOT EXISTS (SELECT 1 FROM tenant_members AS m
		                   WHERE m.tenant_id = t.tenant_id AND m.subject_ref = t.subject_ref AND m.status = 'offboarded')
		 ORDER BY scope`, tenantID, subject, at)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var scope string
			if err := rows.Scan(&scope); err != nil {
				return err
			}
			out.TokenScopes = append(out.TokenScopes, scope)
		}
		return rows.Err()
	})
	return out, err
}
