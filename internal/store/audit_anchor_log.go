// SPDX-License-Identifier: BUSL-1.1

package store

import "context"

// AuditAnchorLog returns all of a tenant's anchors in the order their events
// were appended: the entries of the tenant's anchor log (A148).
func (s *Store) AuditAnchorLog(ctx context.Context, tenantID string) ([]AuditAnchor, error) {
	return s.queryAuditAnchors(ctx, tenantID,
		`SELECT tenant_id::text, event_id, through_sequence, chain_head, anchored_at, token_serial::text, token_sha256,
		        cadence_seconds, event_sequence, recorded_at
		   FROM audit_anchors WHERE tenant_id = $1 ORDER BY event_sequence ASC`,
		tenantID)
}
