package est

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// BasicAuthConfig configures the EST HTTP Basic enrollment gate. Password is
// byte material so callers do not park enrollment secrets in struct strings.
type BasicAuthConfig struct {
	Password         []byte
	MaxFailuresPerIP int
	Window           time.Duration
	Now              func() time.Time
}

// BasicAuthenticator is an EST Authenticator with a per-IP failed-auth limiter.
type BasicAuthenticator struct {
	password []byte
	max      int
	window   time.Duration
	now      func() time.Time

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewBasicAuthenticator returns a Basic authenticator. A zero MaxFailuresPerIP
// disables only the brute-force limiter; authentication itself remains enabled.
func NewBasicAuthenticator(cfg BasicAuthConfig) *BasicAuthenticator {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}
	return &BasicAuthenticator{
		password: append([]byte(nil), cfg.Password...),
		max:      cfg.MaxFailuresPerIP,
		window:   window,
		now:      now,
		failures: make(map[string][]time.Time),
	}
}

// Authenticate implements Authenticator.
func (a *BasicAuthenticator) Authenticate(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || len(a.password) == 0 {
		return false
	}
	return crypto.ConstantTimeEqual([]byte(pass), a.password)
}

func (a *BasicAuthenticator) TooManyFailures(r *http.Request) bool {
	if a == nil || a.max <= 0 {
		return false
	}
	ip := requestIP(r)
	if ip == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.pruneLocked(ip, a.now())
	a.failures[ip] = kept
	return len(kept) >= a.max
}

func (a *BasicAuthenticator) RecordFailure(r *http.Request) {
	if a == nil || a.max <= 0 {
		return
	}
	ip := requestIP(r)
	if ip == "" {
		return
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.pruneLocked(ip, now)
	a.failures[ip] = append(kept, now)
}

func (a *BasicAuthenticator) pruneLocked(ip string, now time.Time) []time.Time {
	cutoff := now.Add(-a.window)
	prior := a.failures[ip]
	kept := prior[:0]
	for _, ts := range prior {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	return kept
}

type windowCounter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

func newWindowCounter(now func() time.Time) *windowCounter {
	if now == nil {
		now = time.Now
	}
	return &windowCounter{hits: make(map[string][]time.Time), now: now}
}

func (w *windowCounter) Allow(key string, max int, window time.Duration) bool {
	if w == nil || max <= 0 || key == "" {
		return true
	}
	if window <= 0 {
		window = time.Minute
	}
	now := w.now()
	cutoff := now.Add(-window)
	w.mu.Lock()
	defer w.mu.Unlock()
	prior := w.hits[key]
	kept := prior[:0]
	for _, ts := range prior {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= max {
		w.hits[key] = kept
		return false
	}
	w.hits[key] = append(kept, now)
	return true
}

func requestIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
