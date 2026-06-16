package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// This file is the S8b.2 DNS-01 reliability layer: it makes DNS-01 dependable in
// production, where it most often fails — the CA being asked to validate before the
// TXT record has propagated, and transient provider-API errors / rate limits. It
// adds (1) a PropagationChecker that confirms a record is visible across every
// authoritative view before the CA validates, (2) a RetryingProvider that backs off
// on transient and rate-limit errors, and (3) PreflightDNS01, an onboarding check
// that surfaces a broken DNS-01 path (e.g. a misconfigured CNAME delegation) before
// a 3am renewal. All of it composes the S8b.1 DNSProvider/Resolver template; none of
// it touches the crypto/signer boundary.

// --- Propagation checking ---------------------------------------------------

// PropagationChecker confirms a published TXT record is observable across all of a
// zone's authoritative views before the CA is asked to validate. Each Resolver
// represents one authoritative nameserver (or vantage point); Wait returns only once
// every Resolver reports the expected value, and fails closed on timeout. Premature
// validation is the single biggest cause of flaky DNS-01, so this is the gate the CA
// request waits behind.
type PropagationChecker struct {
	Resolvers []Resolver    // authoritative views; every one must observe the record
	Interval  time.Duration // poll interval (default 2s)
	Timeout   time.Duration // overall budget (default 120s)

	// sleep is injectable for tests; nil uses a real, context-cancellable sleep.
	sleep func(context.Context, time.Duration) error
}

func (c *PropagationChecker) interval() time.Duration {
	if c.Interval <= 0 {
		return 2 * time.Second
	}
	return c.Interval
}

func (c *PropagationChecker) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 120 * time.Second
	}
	return c.Timeout
}

func (c *PropagationChecker) sleepFor(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Wait blocks until every Resolver observes value at name, or the timeout budget is
// exhausted (measured as the sum of poll intervals, so it is deterministic and does
// not depend on wall-clock drift). A per-view lookup error is treated as "not yet
// visible" (an NXDOMAIN mid-propagation is normal), not a hard failure.
func (c *PropagationChecker) Wait(ctx context.Context, name, value string) error {
	if len(c.Resolvers) == 0 {
		return errors.New("acme: propagation checker has no resolvers")
	}
	var elapsed time.Duration
	budget := c.timeout()
	for {
		if c.allVisible(ctx, name, value) {
			return nil
		}
		if elapsed >= budget {
			return fmt.Errorf("acme: dns-01 record %q not visible on all %d authoritative views within %s",
				name, len(c.Resolvers), budget)
		}
		if err := c.sleepFor(ctx, c.interval()); err != nil {
			return err
		}
		elapsed += c.interval()
	}
}

func (c *PropagationChecker) allVisible(ctx context.Context, name, value string) bool {
	for _, r := range c.Resolvers {
		records, err := r.LookupTXT(ctx, name)
		if err != nil || !containsTXT(records, value) {
			return false
		}
	}
	return true
}

// --- Retry / backoff / rate-limit -------------------------------------------

// RateLimitError marks a provider error as a rate-limit response. The retrying
// wrapper honors RetryAfter and backs off, rather than failing the enrollment.
type RateLimitError struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimitError) Error() string {
	if e.Err != nil {
		return "rate limited: " + e.Err.Error()
	}
	return "rate limited"
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// RetryingProvider wraps a DNSProvider with bounded exponential backoff so a
// transient provider-API error or a rate-limit response is retried rather than
// failing a renewal. It relies on the underlying provider's idempotent contract
// (re-presenting or re-cleaning the same record is safe), so a retry never orphans a
// record (AN-5).
type RetryingProvider struct {
	Provider    DNSProvider
	MaxAttempts int           // default 5
	BaseDelay   time.Duration // default 1s; doubles each attempt
	MaxDelay    time.Duration // cap per wait; default 30s

	// sleep is injectable for tests; nil uses a real, context-cancellable sleep.
	sleep func(context.Context, time.Duration) error
}

var _ DNSProvider = RetryingProvider{}

// PresentTXT publishes name=value, retrying on transient/rate-limit errors.
func (r RetryingProvider) PresentTXT(ctx context.Context, name, value string) error {
	return r.retry(ctx, func() error { return r.Provider.PresentTXT(ctx, name, value) })
}

// CleanupTXT removes name=value, retrying on transient/rate-limit errors.
func (r RetryingProvider) CleanupTXT(ctx context.Context, name, value string) error {
	return r.retry(ctx, func() error { return r.Provider.CleanupTXT(ctx, name, value) })
}

func (r RetryingProvider) retry(ctx context.Context, op func() error) error {
	attempts := r.MaxAttempts
	if attempts <= 0 {
		attempts = 5
	}
	delay := r.BaseDelay
	if delay <= 0 {
		delay = time.Second
	}
	maxDelay := r.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}

	var err error
	for i := 0; i < attempts; i++ {
		if err = op(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		wait := delay
		var rl *RateLimitError
		if errors.As(err, &rl) && rl.RetryAfter > wait {
			wait = rl.RetryAfter // honor the server-advertised backoff
		}
		if wait > maxDelay {
			wait = maxDelay
		}
		if serr := r.sleepFor(ctx, wait); serr != nil {
			return serr
		}
		delay *= 2
	}
	return fmt.Errorf("acme: dns provider failed after %d attempts: %w", attempts, err)
}

func (r RetryingProvider) sleepFor(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- Pre-flight -------------------------------------------------------------

// PreflightDNS01 verifies a domain's DNS-01 path end to end at onboarding: it
// publishes a unique random probe TXT through the provider, confirms it propagates
// across every authoritative view, then cleans it up. A misconfiguration — a missing
// zone delegation, a broken acme-dns CNAME (S8b.3), or wrong credentials — surfaces
// now rather than at a renewal. The probe value is random so a stale record can never
// mask a broken path.
func PreflightDNS01(ctx context.Context, provider DNSProvider, checker *PropagationChecker, domain string) error {
	if provider == nil || checker == nil {
		return errors.New("acme: preflight requires a provider and a propagation checker")
	}
	name := DNS01RecordName(domain)
	probe, err := crypto.RandomBytes(16)
	if err != nil {
		return fmt.Errorf("acme: preflight probe: %w", err)
	}
	value := crypto.SHA256Base64URL(probe)

	if err := provider.PresentTXT(ctx, name, value); err != nil {
		return fmt.Errorf("acme: preflight present %s: %w", name, err)
	}
	defer func() { _ = provider.CleanupTXT(ctx, name, value) }()

	if err := checker.Wait(ctx, name, value); err != nil {
		return fmt.Errorf("acme: preflight %s: %w", domain, err)
	}
	return nil
}
