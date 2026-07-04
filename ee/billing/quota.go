// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const CodeQuotaExhausted = "quota_exhausted"

var ErrQuotaExhausted = errors.New("billing: quota_exhausted")

type TenantCounter func(context.Context, string) (TenantCounts, error)

type QuotaError struct {
	Code     string
	TenantID string
	Resource string
	Current  int64
	Limit    int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("quota exhausted: tenant %s has %d of %d %s", e.TenantID, e.Current, e.Limit, e.Resource)
}

func (e *QuotaError) Is(target error) bool {
	return target == ErrQuotaExhausted
}

type QuotaChecker struct {
	store Store
	count TenantCounter
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cachedQuota
}

type cachedQuota struct {
	quota   Quota
	fetched time.Time
}

func NewQuotaChecker(store Store, count TenantCounter, ttl time.Duration) *QuotaChecker {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if count == nil {
		count = func(context.Context, string) (TenantCounts, error) { return TenantCounts{}, nil }
	}
	return &QuotaChecker{store: store, count: count, ttl: ttl, now: time.Now, cache: map[string]cachedQuota{}}
}

func (q *QuotaChecker) AllowCreate(ctx context.Context, tenantID, resource string) error {
	if q == nil || q.store == nil || tenantID == "" || resource == "" {
		return nil
	}
	quota, err := q.quota(ctx, tenantID)
	if err != nil {
		return nil
	}
	limit := quota.LimitFor(resource)
	if limit == nil {
		return nil
	}
	counts, err := q.count(ctx, tenantID)
	if err != nil {
		return nil
	}
	current := counts[resource]
	if current >= int64(*limit) {
		return &QuotaError{Code: CodeQuotaExhausted, TenantID: tenantID, Resource: resource, Current: current, Limit: *limit}
	}
	return nil
}

func (q *QuotaChecker) Invalidate(tenantID string) {
	q.mu.Lock()
	delete(q.cache, tenantID)
	q.mu.Unlock()
}

func (q *QuotaChecker) quota(ctx context.Context, tenantID string) (Quota, error) {
	q.mu.Lock()
	if cached, ok := q.cache[tenantID]; ok && q.now().Sub(cached.fetched) < q.ttl {
		q.mu.Unlock()
		return cached.quota, nil
	}
	q.mu.Unlock()
	quota, err := q.store.QuotaFor(ctx, tenantID)
	if err != nil {
		return Quota{}, err
	}
	q.mu.Lock()
	q.cache[tenantID] = cachedQuota{quota: quota, fetched: q.now()}
	q.mu.Unlock()
	return quota, nil
}
