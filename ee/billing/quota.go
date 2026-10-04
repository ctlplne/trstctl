// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/usage"
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
	// Matches BOTH sentinels: this package's own, and core's usage sentinel —
	// the handlers that turn a refusal into a 429 live in core and cannot
	// import this package (AN-9), so the classification contract is core's.
	return target == ErrQuotaExhausted || target == usage.ErrQuotaExhausted
}

type QuotaChecker struct {
	store   Store
	count   TenantCounter
	admitMu sync.Mutex // only the non-durable in-memory installation uses this
}

// The duration argument is retained for the attach API, but quota decisions
// never cache a cap: a Provider's lowered limit must apply on the next create.
func NewQuotaChecker(store Store, count TenantCounter, _ time.Duration) *QuotaChecker {
	if count == nil {
		count = func(context.Context, string) (TenantCounts, error) {
			return nil, errors.New("billing: resource counter is not configured")
		}
	}
	return &QuotaChecker{store: store, count: count}
}

func (q *QuotaChecker) AllowCreate(ctx context.Context, tenantID, resource string) error {
	if q == nil || q.store == nil || tenantID == "" || resource == "" {
		return fmt.Errorf("%w: billing quota admission is not configured", usage.ErrQuotaUnavailable)
	}
	quota, err := q.store.QuotaFor(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("%w: billing read tenant quota: %w", usage.ErrQuotaUnavailable, err)
	}
	limit := quota.LimitFor(resource)
	if limit == nil {
		return nil
	}
	counts, err := q.count(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("%w: billing count tenant resources: %w", usage.ErrQuotaUnavailable, err)
	}
	current := counts[resource]
	if current >= int64(*limit) {
		return &QuotaError{Code: CodeQuotaExhausted, TenantID: tenantID, Resource: resource, Current: current, Limit: *limit}
	}
	return nil
}

func (q *QuotaChecker) WithCreationFence(ctx context.Context, tenantID, resource string, fn func(context.Context) error) error {
	if q == nil || q.store == nil || fn == nil {
		return fmt.Errorf("%w: billing quota creation fence is not configured", usage.ErrQuotaUnavailable)
	}
	if durable, ok := q.store.(*PGStore); ok {
		if durable.store == nil {
			return fmt.Errorf("%w: billing durable quota creation fence has no datastore", usage.ErrQuotaUnavailable)
		}
		return durable.store.WithTenantResourceCreation(ctx, tenantID, resource, fn)
	}
	q.admitMu.Lock()
	defer q.admitMu.Unlock()
	return fn(ctx)
}
