package api

import (
	"sync"
	"time"
)

const (
	defaultSpecialRouteAbuseWindow         = time.Minute
	defaultSpecialRouteAbuseGlobal         = 1200
	defaultSpecialRouteAbusePerSource      = 120
	defaultSpecialRouteAbusePerToken       = 60
	defaultSpecialRouteAbusePerTenant      = 300
	defaultOIDCPreLoginMaxEntries          = 10000
	defaultOIDCPreLoginMaxEntriesPerSource = 100
)

// SpecialRouteAbuseLimits bounds public auth, enrollment, and SCIM routes that
// live outside the normal authenticated route registry. Zero fields select
// conservative defaults; every API instance gets a limiter even when this option
// is not set.
type SpecialRouteAbuseLimits struct {
	Window            time.Duration
	Global            int
	PerSource         int
	PerToken          int
	PerTenant         int
	PreLoginGlobal    int
	PreLoginPerSource int
}

// WithSpecialRouteAbuseLimits overrides the default special-route abuse budgets.
// It is primarily used by tests and small deployments that need tighter public
// endpoint budgets than the default served path.
func WithSpecialRouteAbuseLimits(limits SpecialRouteAbuseLimits) Option {
	return func(c *config) { c.specialAbuseLimits = limits.withDefaults() }
}

func (l SpecialRouteAbuseLimits) withDefaults() SpecialRouteAbuseLimits {
	if l.Window <= 0 {
		l.Window = defaultSpecialRouteAbuseWindow
	}
	if l.Global <= 0 {
		l.Global = defaultSpecialRouteAbuseGlobal
	}
	if l.PerSource <= 0 {
		l.PerSource = defaultSpecialRouteAbusePerSource
	}
	if l.PerToken <= 0 {
		l.PerToken = defaultSpecialRouteAbusePerToken
	}
	if l.PerTenant <= 0 {
		l.PerTenant = defaultSpecialRouteAbusePerTenant
	}
	if l.PreLoginGlobal <= 0 {
		l.PreLoginGlobal = defaultOIDCPreLoginMaxEntries
	}
	if l.PreLoginPerSource <= 0 {
		l.PreLoginPerSource = defaultOIDCPreLoginMaxEntriesPerSource
	}
	return l
}

func (l SpecialRouteAbuseLimits) preLoginLimits() oidcPreLoginLimits {
	l = l.withDefaults()
	return oidcPreLoginLimits{MaxEntries: l.PreLoginGlobal, MaxPerSource: l.PreLoginPerSource}
}

type specialRouteAbuseRequest struct {
	Source   string
	TokenKey string
	TenantID string
}

type specialRouteAbuseLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	limits  SpecialRouteAbuseLimits
	global  abuseCounter
	sources map[string]abuseCounter
	tokens  map[string]abuseCounter
	tenants map[string]abuseCounter
}

type abuseCounter struct {
	Count int
	Reset time.Time
}

func newSpecialRouteAbuseLimiter(limits SpecialRouteAbuseLimits) *specialRouteAbuseLimiter {
	return &specialRouteAbuseLimiter{
		now:     time.Now,
		limits:  limits.withDefaults(),
		sources: map[string]abuseCounter{},
		tokens:  map[string]abuseCounter{},
		tenants: map[string]abuseCounter{},
	}
}

func (l *specialRouteAbuseLimiter) allow(req specialRouteAbuseRequest) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	global := l.activeCounter(l.global, now)
	if retryAfter, denied := denyRetryAfter(global, l.limits.Global, now); denied {
		return false, retryAfter
	}
	source := l.activeMapCounter(l.sources, req.Source, now)
	if retryAfter, denied := denyRetryAfter(source, l.limits.PerSource, now); denied {
		return false, retryAfter
	}
	token := l.activeMapCounter(l.tokens, req.TokenKey, now)
	if retryAfter, denied := denyRetryAfter(token, l.limits.PerToken, now); denied {
		return false, retryAfter
	}
	tenant := l.activeMapCounter(l.tenants, req.TenantID, now)
	if retryAfter, denied := denyRetryAfter(tenant, l.limits.PerTenant, now); denied {
		return false, retryAfter
	}

	l.global = incrementCounter(global)
	if req.Source != "" {
		l.sources[req.Source] = incrementCounter(source)
	}
	if req.TokenKey != "" {
		l.tokens[req.TokenKey] = incrementCounter(token)
	}
	if req.TenantID != "" {
		l.tenants[req.TenantID] = incrementCounter(tenant)
	}
	return true, 0
}

func (l *specialRouteAbuseLimiter) activeCounter(c abuseCounter, now time.Time) abuseCounter {
	if c.Reset.IsZero() || !now.Before(c.Reset) {
		return abuseCounter{Reset: now.Add(l.limits.Window)}
	}
	return c
}

func (l *specialRouteAbuseLimiter) activeMapCounter(m map[string]abuseCounter, key string, now time.Time) abuseCounter {
	if key == "" {
		return abuseCounter{Reset: now.Add(l.limits.Window)}
	}
	return l.activeCounter(m[key], now)
}

func (l *specialRouteAbuseLimiter) pruneLocked(now time.Time) {
	pruneAbuseCounters(l.sources, now)
	pruneAbuseCounters(l.tokens, now)
	pruneAbuseCounters(l.tenants, now)
}

func pruneAbuseCounters(m map[string]abuseCounter, now time.Time) {
	for key, counter := range m {
		if counter.Reset.IsZero() || !now.Before(counter.Reset) {
			delete(m, key)
		}
	}
}

func denyRetryAfter(c abuseCounter, limit int, now time.Time) (time.Duration, bool) {
	if limit <= 0 || c.Count < limit {
		return 0, false
	}
	retryAfter := c.Reset.Sub(now)
	if retryAfter <= 0 {
		retryAfter = time.Second
	}
	return retryAfter, true
}

func incrementCounter(c abuseCounter) abuseCounter {
	c.Count++
	return c
}
