// SPDX-License-Identifier: MPL-2.0

package store

import "context"

// QueueSummary is a deployment-wide count-only support diagnostic. It excludes
// tenant IDs, destinations, payloads, idempotency keys, and error text.
type QueueSummary struct {
	Pending    int64 `json:"pending"`
	Processing int64 `json:"processing"`
	Failed     int64 `json:"failed"`
	Delivered  int64 `json:"delivered"`
}

// SupportQueueSummary returns aggregate outbox posture for the offline support
// bundle. This is deliberately a count-only system query: no tenant identity or
// row content leaves the store.
func (s *Store) SupportQueueSummary(ctx context.Context) (QueueSummary, error) {
	var out QueueSummary
	//trstctl:system-query — cross-tenant by design: support diagnostics expose only deployment-wide status counts and no tenant/destination/payload fields.
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE status = 'pending'),
		        count(*) FILTER (WHERE status = 'processing'),
		        count(*) FILTER (WHERE status = 'failed'),
		        count(*) FILTER (WHERE status = 'delivered')
		   FROM outbox
		  WHERE tenant_id IS NOT NULL`).Scan(
		&out.Pending, &out.Processing, &out.Failed, &out.Delivered)
	return out, err
}
