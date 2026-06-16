// Package secretsdk is the secrets SDK core (S19.2, F64): a client that fetches
// secrets and short-lived credentials, caches them, auto-refreshes before expiry,
// and fails safe — a revoked credential is rejected on the next refresh. This Go
// SDK is the reference; the Python/Node/Java SDKs follow the same template and the
// shared conformance behavior exercised here. Cached material is []byte and never
// logged (AN-8).
package secretsdk

import (
	"context"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Fetcher retrieves a secret and its expiry from the serving secrets engine. It
// encapsulates auth-method/attestation login; a revoked credential surfaces as an
// error here.
type Fetcher interface {
	Fetch(ctx context.Context, path string) (value []byte, expiresAt time.Time, err error)
}

// Client caches and auto-refreshes secrets.
//
// A Client is scoped to a single tenant (AN-1): TenantID identifies the caller's
// tenant and the Fetcher it is constructed with must be that tenant's
// (tenant-scoped login/lease engine), so a Client never serves another tenant's
// secret. The in-memory cache is per-Client and therefore per-tenant by
// construction. The server-side handler that mints a Client for an incoming
// request must derive TenantID from the authenticated caller, not from the request
// body (the wiring of that served handler is tracked in docs/limitations.md).
type Client struct {
	tenantID string
	fetcher  Fetcher
	clock    func() time.Time
	fraction float64 // refresh once this fraction of lifetime has elapsed
	mu       sync.Mutex
	cache    map[string]entry
}

type entry struct {
	value     []byte
	issuedAt  time.Time
	expiresAt time.Time
}

// Option configures a Client.
type Option func(*Client)

// WithClock overrides the clock (tests).
func WithClock(f func() time.Time) Option { return func(c *Client) { c.clock = f } }

// WithRefreshFraction sets the lifetime fraction after which Get refreshes.
func WithRefreshFraction(f float64) Option { return func(c *Client) { c.fraction = f } }

// WithTenant scopes the Client to a tenant (AN-1). The Fetcher must be that
// tenant's; the tenant id is carried for attribution and so a server-side caller
// constructs one Client per tenant (the cache is per-Client, hence per-tenant).
func WithTenant(tenantID string) Option { return func(c *Client) { c.tenantID = tenantID } }

// New constructs a Client.
func New(fetcher Fetcher, opts ...Option) *Client {
	c := &Client{fetcher: fetcher, clock: time.Now, fraction: 0.5, cache: map[string]entry{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// TenantID returns the tenant this Client is scoped to (empty for a bare,
// single-tenant embed), so callers and tests can assert tenant attribution (AN-1).
func (c *Client) TenantID() string { return c.tenantID }

// Get returns a secret, serving from cache while fresh and refreshing once the
// refresh threshold is passed. A refresh failure (e.g. a revoked credential)
// evicts the cache entry and returns an error — fail-safe, never a stale secret.
//
// The cache owns the canonical secret bytes so it can zeroize them on eviction or
// replacement (AN-8); callers receive a fresh copy each call and own its lifetime.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	c.mu.Lock()
	e, ok := c.cache[path]
	c.mu.Unlock()
	now := c.clock()
	if ok && now.Before(c.refreshAt(e)) {
		return append([]byte(nil), e.value...), nil
	}
	value, expiresAt, err := c.fetcher.Fetch(ctx, path)
	if err != nil {
		c.mu.Lock()
		if old, had := c.cache[path]; had {
			secret.Wipe(old.value) // zeroize the evicted secret (AN-8)
		}
		delete(c.cache, path)
		c.mu.Unlock()
		return nil, fmt.Errorf("secretsdk: refresh failed (fail-safe): %w", err)
	}
	// The cache keeps its own copy so it can safely zeroize on evict/replace without
	// touching the Fetcher's or any caller's slice (AN-8).
	cached := append([]byte(nil), value...)
	c.mu.Lock()
	if old, had := c.cache[path]; had {
		secret.Wipe(old.value) // zeroize the prior cached value before replacing it (AN-8)
	}
	c.cache[path] = entry{value: cached, issuedAt: now, expiresAt: expiresAt}
	c.mu.Unlock()
	return append([]byte(nil), value...), nil
}

// Evict zeroizes and removes the cached secret for path (AN-8). The next Get
// re-fetches. A no-op if nothing is cached.
func (c *Client) Evict(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[path]; ok {
		secret.Wipe(e.value)
		delete(c.cache, path)
	}
}

// Close zeroizes and drops every cached secret (AN-8). Call it when the client is
// retired so no secret bytes linger in freed heap.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, e := range c.cache {
		secret.Wipe(e.value)
		delete(c.cache, path)
	}
}

func (c *Client) refreshAt(e entry) time.Time {
	life := e.expiresAt.Sub(e.issuedAt)
	if life <= 0 {
		return e.issuedAt // always refresh
	}
	return e.issuedAt.Add(time.Duration(float64(life) * c.fraction))
}
