// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Change impact (A244): before a deployment target or a certificate profile
// changes, which identities it reaches and which open approvals the change
// would supersede.

// ImpactIdentity is one identity a change reaches.
type ImpactIdentity struct {
	ID      string
	Name    string
	Status  string
	OwnerID string
}

// ImpactApproval is one open approval a change would supersede.
type ImpactApproval struct {
	ID         string
	IdentityID string
	Action     string
	Status     string
}

const impactLimit = 500

// IdentitiesWithAttribute lists the identities whose attribute key equals
// value (deployment_target_id for a target, profile_name for a profile).
func (s *Store) IdentitiesWithAttribute(ctx context.Context, tenantID, key, value string) ([]ImpactIdentity, error) {
	var out []ImpactIdentity
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, name, status, coalesce(owner_id::text, '')
			  FROM identities
			 WHERE tenant_id = $1 AND attributes->>$2 = $3
			 ORDER BY name, id LIMIT $4`, tenantID, key, value, impactLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i ImpactIdentity
			if err := rows.Scan(&i.ID, &i.Name, &i.Status, &i.OwnerID); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// OpenApprovalsWithEvidence lists the pending and approved identity approvals
// whose evidence carries ref exactly.
func (s *Store) OpenApprovalsWithEvidence(ctx context.Context, tenantID, ref string) ([]ImpactApproval, error) {
	var out []ImpactApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, resource_id, action, status
			  FROM operation_approval_requests
			 WHERE tenant_id = $1 AND resource_kind = 'identity' AND status IN ('pending', 'approved')
			   AND evidence_refs @> jsonb_build_array($2::text)
			 ORDER BY created_at, id LIMIT $3`, tenantID, ref, impactLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a ImpactApproval
			if err := rows.Scan(&a.ID, &a.IdentityID, &a.Action, &a.Status); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// DestinationApprovalEvidence is the evidence ref an approval carries for a
// deployment target (A244).
func DestinationApprovalEvidence(targetID string) string {
	return operationApprovalEvidenceDestinationTargetPrefix + targetID
}

// ProfileApprovalEvidence is the evidence ref an approval carries for a
// profile name.
func ProfileApprovalEvidence(name string) string {
	return operationApprovalEvidenceProfileNamePrefix + name
}
