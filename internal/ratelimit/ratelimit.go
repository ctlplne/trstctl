// Package ratelimit is the PostgreSQL-backed per-tenant rate limiter (R2.3): a
// token bucket persisted in the rate_limits table, so the limit holds across every
// control-plane replica without a separate datastore (no Redis — CLAUDE.md). It
// implements the api.RateLimiter shape so the API guard can shed load per
// authenticated tenant.
package ratelimit

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Postgres is a token-bucket limiter over store.RateLimitTake.
type Postgres struct {
	store    *store.Store
	capacity float64
	refill   float64 // tokens per second
	bucket   string
}

// NewPostgres returns a limiter admitting bursts up to capacity and refilling at
// refillPerSec tokens/second, keyed per tenant under the "api" bucket.
func NewPostgres(st *store.Store, capacity, refillPerSec float64) *Postgres {
	return &Postgres{store: st, capacity: capacity, refill: refillPerSec, bucket: "api"}
}

// FromRate builds a limiter from a "requests per window" budget: it admits a burst
// of `requests` and refills steadily over `window`.
func FromRate(st *store.Store, requests int, window time.Duration) *Postgres {
	capacity := float64(requests)
	refill := 0.0
	if window > 0 {
		refill = capacity / window.Seconds()
	}
	return NewPostgres(st, capacity, refill)
}

// Allow takes one token for tenantID. allowed is false when the tenant is over
// budget; retryAfter reports when a token will next be available.
func (p *Postgres) Allow(ctx context.Context, tenantID string) (allowed bool, retryAfter time.Duration, err error) {
	return p.store.RateLimitTake(ctx, tenantID, p.bucket, p.capacity, p.refill)
}
