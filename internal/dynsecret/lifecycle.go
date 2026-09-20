// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"time"
)

// Lifecycle is the lease behavior consumed by the served API and expiry worker.
// Engine is the in-memory/reference implementation; production supplies a
// PostgreSQL/event/outbox-backed implementation so lease state survives restart.
type Lifecycle interface {
	Issue(ctx context.Context, provider, role string, ttl time.Duration, idempotencyKey string) (Lease, []byte, error)
	Renew(ctx context.Context, leaseID string, extend time.Duration) (Lease, error)
	Revoke(ctx context.Context, leaseID string) error
	GetLease(leaseID string) (Lease, error)
	ExpireDue(ctx context.Context, now time.Time) (int, error)
	RunRevocations(ctx context.Context) (int, error)
}

var _ Lifecycle = (*Engine)(nil)
