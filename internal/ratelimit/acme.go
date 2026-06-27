package ratelimit

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// ACMEAccountOrders is a PostgreSQL-backed account-keyed ACME new-order limiter.
// The tenant boundary is enforced by store.RateLimitTake under RLS (AN-1).
type ACMEAccountOrders struct {
	store *store.Store
}

// NewACMEAccountOrders returns an ACME account limiter backed by the shared
// rate_limits table. The per-hour budget is supplied per call from ACMEQuota so
// config reload/test setup can reuse the same limiter shape.
func NewACMEAccountOrders(st *store.Store) *ACMEAccountOrders {
	return &ACMEAccountOrders{store: st}
}

// AllowNewOrder takes one token from tenantID/accountURL's ACME new-order bucket.
func (l *ACMEAccountOrders) AllowNewOrder(ctx context.Context, tenantID, accountURL string, perHour int) (bool, time.Duration, error) {
	if perHour <= 0 {
		return true, 0, nil
	}
	if l == nil || l.store == nil {
		return false, 0, errors.New("ratelimit: ACME account limiter store is not configured")
	}
	if tenantID == "" {
		return false, 0, errors.New("ratelimit: ACME account limiter tenant_id is required")
	}
	capacity := float64(perHour)
	return l.store.RateLimitTake(ctx, tenantID, "acme:new-order:"+accountURL, capacity, capacity/time.Hour.Seconds())
}
