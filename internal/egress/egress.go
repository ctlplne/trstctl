// Package egress provides the product-wide outbound HTTP guard used by air-gapped
// installs. It fails closed for public destinations unless the operator explicitly
// allowlists a host or CIDR.
package egress

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// ErrBlocked is returned when the guard refuses outbound egress.
var ErrBlocked = errors.New("egress blocked")

// Config is the operator policy for the egress guard.
type Config struct {
	Enabled      bool
	AllowPrivate bool
	AllowHosts   []string
	AllowCIDRs   []string
}

// Guard enforces outbound HTTP policy and records blocked attempts.
type Guard struct {
	enabled      bool
	allowPrivate bool
	allowHosts   map[string]struct{}
	allowCIDRs   []netip.Prefix
	trips        atomic.Int64
}

// NewGuard builds an egress guard from validated-looking operator config. CIDRs
// are parsed here too so callers get a fail-closed startup error for bad policy.
func NewGuard(cfg Config) (*Guard, error) {
	g := &Guard{
		enabled:      cfg.Enabled,
		allowPrivate: cfg.AllowPrivate,
		allowHosts:   map[string]struct{}{},
	}
	for _, host := range cfg.AllowHosts {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		g.allowHosts[host] = struct{}{}
	}
	for _, raw := range cfg.AllowCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("egress allow_cidrs %q: %w", raw, err)
		}
		g.allowCIDRs = append(g.allowCIDRs, prefix)
	}
	return g, nil
}

// Enabled reports whether the guard is enforcing policy.
func (g *Guard) Enabled() bool { return g != nil && g.enabled }

// Trips returns the number of blocked egress attempts.
func (g *Guard) Trips() int64 {
	if g == nil {
		return 0
	}
	return g.trips.Load()
}

// ResetTrips clears the trip counter. Tests use this after proving the tripwire.
func (g *Guard) ResetTrips() {
	if g != nil {
		g.trips.Store(0)
	}
}

// CheckURL validates a raw outbound URL against the guard policy.
func (g *Guard) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		if g != nil && g.enabled {
			g.trips.Add(1)
		}
		return fmt.Errorf("%w: invalid URL", ErrBlocked)
	}
	return g.CheckRequestURL(u)
}

// CheckRequestURL validates a request URL against the guard policy.
func (g *Guard) CheckRequestURL(u *url.URL) error {
	if g == nil || !g.enabled {
		return nil
	}
	if u == nil || u.Host == "" {
		g.trips.Add(1)
		return fmt.Errorf("%w: missing destination host", ErrBlocked)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		g.trips.Add(1)
		return fmt.Errorf("%w: unsupported outbound scheme %q", ErrBlocked, u.Scheme)
	}
	host := normalizeHost(u.Host)
	if g.allowedHost(host) {
		return nil
	}
	g.trips.Add(1)
	return fmt.Errorf("%w: %s is not allowlisted", ErrBlocked, host)
}

// WrapTransport returns a RoundTripper that checks every outbound request before
// delegating to the wrapped transport.
func (g *Guard) WrapTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if g == nil || !g.enabled {
		return base
	}
	return roundTripper{guard: g, base: base}
}

// Client returns a guarded HTTP client. A non-positive timeout leaves the client
// with the standard library's no-deadline behavior.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: g.WrapTransport(http.DefaultTransport), Timeout: timeout}
}

type roundTripper struct {
	guard *Guard
	base  http.RoundTripper
}

func (r roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := r.guard.CheckRequestURL(req.URL); err != nil {
		return nil, err
	}
	return r.base.RoundTrip(req)
}

func (g *Guard) allowedHost(host string) bool {
	if host == "" {
		return false
	}
	if _, ok := g.allowHosts[host]; ok {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err == nil {
		if g.allowPrivate && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
			return true
		}
		for _, prefix := range g.allowCIDRs {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	return g.allowPrivate && (host == "localhost" || strings.HasSuffix(host, ".localhost"))
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(host, ".")
}
