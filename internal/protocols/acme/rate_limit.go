package acme

import (
	"context"
	"sync"
	"time"
)

// AccountOrderLimiter is the account-keyed order/hour bulkhead. The ACME server
// depends on this small shape so served deployments can use PostgreSQL-backed
// buckets while protocol tests can stay storage-free.
type AccountOrderLimiter interface {
	AllowNewOrder(ctx context.Context, tenantID, accountURL string, perHour int) (allowed bool, retryAfter time.Duration, err error)
}

type memoryAccountOrderLimiter struct {
	mu      sync.Mutex
	clock   func() time.Time
	buckets map[string]*memoryOrderBucket
}

type memoryOrderBucket struct {
	capacity   float64
	refillRate float64
	tokens     float64
	updated    time.Time
}

func newMemoryAccountOrderLimiter() *memoryAccountOrderLimiter {
	return &memoryAccountOrderLimiter{clock: time.Now, buckets: map[string]*memoryOrderBucket{}}
}

func (l *memoryAccountOrderLimiter) AllowNewOrder(_ context.Context, tenantID, accountURL string, perHour int) (bool, time.Duration, error) {
	if perHour <= 0 {
		return true, 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	key := tenantID + "|" + accountURL
	capacity := float64(perHour)
	refill := capacity / time.Hour.Seconds()
	b := l.buckets[key]
	if b == nil {
		b = &memoryOrderBucket{capacity: capacity, refillRate: refill, tokens: capacity, updated: now}
		l.buckets[key] = b
	}
	if b.capacity != capacity {
		b.capacity = capacity
		b.refillRate = refill
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.updated = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0, nil
	}
	if b.refillRate <= 0 {
		return false, time.Hour, nil
	}
	return false, time.Duration((1-b.tokens)/b.refillRate) * time.Second, nil
}
