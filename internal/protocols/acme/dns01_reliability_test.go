// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// recSleep returns an injectable sleep that records requested backoff durations
// without actually waiting, so reliability tests are deterministic and fast.
func recSleep(rec *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*rec = append(*rec, d)
		return nil
	}
}

func noSleep(context.Context, time.Duration) error { return nil }

// relGatedResolver reports value only after visibleAfter lookups, modelling DNS
// propagation delay on one authoritative view.
type relGatedResolver struct {
	value        string
	visibleAfter int
	calls        int
}

func (r *relGatedResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.calls++
	if r.calls >= r.visibleAfter {
		return []string{r.value}, nil
	}
	return nil, nil
}

// relFlakyProvider fails failFirst times then succeeds; counts calls.
type relFlakyProvider struct {
	failFirst int
	err       error
	calls     int
}

func (p *relFlakyProvider) PresentTXT(context.Context, string, string) error {
	p.calls++
	if p.calls <= p.failFirst {
		if p.err != nil {
			return p.err
		}
		return errors.New("transient provider error")
	}
	return nil
}
func (p *relFlakyProvider) CleanupTXT(context.Context, string, string) error { return nil }

// relRateLimitProvider returns a RateLimitError on the first call, then succeeds.
type relRateLimitProvider struct {
	retryAfter time.Duration
	calls      int
}

func (p *relRateLimitProvider) PresentTXT(context.Context, string, string) error {
	p.calls++
	if p.calls == 1 {
		return &RateLimitError{RetryAfter: p.retryAfter}
	}
	return nil
}
func (p *relRateLimitProvider) CleanupTXT(context.Context, string, string) error { return nil }

// relBrokenProvider accepts present/cleanup but never actually publishes — a broken
// zone delegation: the record never becomes visible.
type relBrokenProvider struct{}

func (relBrokenProvider) PresentTXT(context.Context, string, string) error { return nil }
func (relBrokenProvider) CleanupTXT(context.Context, string, string) error { return nil }

func TestPropagationCheckerWaitsForAllViews(t *testing.T) {
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "the-digest"
	ready := &MemoryDNSProvider{}
	_ = ready.PresentTXT(ctx, name, value) // one view already sees the record
	gated := &relGatedResolver{value: value, visibleAfter: 3}
	var slept []time.Duration
	c := &PropagationChecker{
		Resolvers: []Resolver{ready, gated},
		Interval:  time.Second,
		Timeout:   time.Minute,
		sleep:     recSleep(&slept),
	}
	if err := c.Wait(ctx, name, value); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if gated.calls < 3 {
		t.Errorf("lagging view polled %d times, want >=3 (must wait for propagation)", gated.calls)
	}
	if len(slept) < 2 {
		t.Errorf("checker backed off %d times, want >=2 between polls", len(slept))
	}
}

func TestPropagationCheckerTimesOut(t *testing.T) {
	const name, value = "_acme-challenge.example.com", "never"
	gated := &relGatedResolver{value: value, visibleAfter: 1 << 30} // never within budget
	var slept []time.Duration
	c := &PropagationChecker{
		Resolvers: []Resolver{gated},
		Interval:  time.Second,
		Timeout:   5 * time.Second,
		sleep:     recSleep(&slept),
	}
	err := c.Wait(context.Background(), name, value)
	if err == nil {
		t.Fatal("Wait succeeded but the record never propagated")
	}
	if !strings.Contains(err.Error(), "not visible") {
		t.Errorf("want a propagation-timeout error, got: %v", err)
	}
}

// TestSolverWaitsForPropagation proves the solver itself waits for the record to be
// authoritatively visible before returning (so the CA is not asked to validate too
// early) — the headline S8b.2 acceptance.
func TestSolverWaitsForPropagation(t *testing.T) {
	ctx := context.Background()
	const domain, keyAuth = "example.com", "tok.thumb"
	name := DNS01RecordName(domain)
	value := DNS01RecordValue(keyAuth)
	mem := &MemoryDNSProvider{}
	gated := &relGatedResolver{value: value, visibleAfter: 3}
	var slept []time.Duration
	solver := DNS01Solver{
		Provider: mem,
		Propagation: &PropagationChecker{
			Resolvers: []Resolver{gated}, Interval: time.Second, Timeout: time.Minute, sleep: recSleep(&slept),
		},
	}
	cleanup, err := solver.Present(ctx, domain, keyAuth)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got, _ := mem.LookupTXT(ctx, name); !containsTXT(got, value) {
		t.Error("record was not published to the provider")
	}
	if len(slept) == 0 {
		t.Error("solver returned without waiting for propagation")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestSolverPropagationFailsClosed(t *testing.T) {
	ctx := context.Background()
	const domain, keyAuth = "example.com", "tok.thumb"
	name := DNS01RecordName(domain)
	value := DNS01RecordValue(keyAuth)
	mem := &MemoryDNSProvider{}
	neverVisible := &relGatedResolver{value: value, visibleAfter: 1 << 30}
	solver := DNS01Solver{
		Provider: mem,
		Propagation: &PropagationChecker{
			Resolvers: []Resolver{neverVisible}, Interval: time.Second, Timeout: 3 * time.Second, sleep: noSleep,
		},
	}
	if _, err := solver.Present(ctx, domain, keyAuth); err == nil {
		t.Fatal("Present succeeded despite no propagation")
	}
	if got, _ := mem.LookupTXT(ctx, name); containsTXT(got, value) {
		t.Error("solver did not retract the record after a propagation failure (orphaned record)")
	}
}

func TestRetryingProviderRetriesTransient(t *testing.T) {
	flaky := &relFlakyProvider{failFirst: 2}
	var slept []time.Duration
	rp := RetryingProvider{Provider: flaky, MaxAttempts: 5, BaseDelay: time.Second, sleep: recSleep(&slept)}
	if err := rp.PresentTXT(context.Background(), "n", "v"); err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	if flaky.calls != 3 {
		t.Errorf("underlying called %d times, want 3 (2 transient failures + 1 success)", flaky.calls)
	}
	if len(slept) != 2 {
		t.Errorf("backed off %d times, want 2", len(slept))
	}
}

func TestRetryingProviderExhausts(t *testing.T) {
	flaky := &relFlakyProvider{failFirst: 100, err: errors.New("boom")}
	var slept []time.Duration
	rp := RetryingProvider{Provider: flaky, MaxAttempts: 3, BaseDelay: time.Second, sleep: recSleep(&slept)}
	if err := rp.PresentTXT(context.Background(), "n", "v"); err == nil {
		t.Fatal("expected failure after exhausting attempts")
	}
	if flaky.calls != 3 {
		t.Errorf("underlying called %d times, want 3 (MaxAttempts)", flaky.calls)
	}
}

// TestRetryingProviderHonorsRateLimit: a rate-limit response backs off for at least
// the advertised RetryAfter rather than the (smaller) base delay.
func TestRetryingProviderHonorsRateLimit(t *testing.T) {
	const retryAfter = 7 * time.Second
	rl := &relRateLimitProvider{retryAfter: retryAfter}
	var slept []time.Duration
	rp := RetryingProvider{Provider: rl, MaxAttempts: 3, BaseDelay: time.Second, sleep: recSleep(&slept)}
	if err := rp.PresentTXT(context.Background(), "n", "v"); err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	if len(slept) == 0 || slept[0] != retryAfter {
		t.Errorf("first backoff = %v, want the advertised RetryAfter %v", slept, retryAfter)
	}
}

func TestPreflightHealthy(t *testing.T) {
	ctx := context.Background()
	mem := &MemoryDNSProvider{}
	c := &PropagationChecker{Resolvers: []Resolver{mem}, Interval: time.Second, Timeout: time.Minute, sleep: noSleep}
	if err := PreflightDNS01(ctx, mem, c, "example.com"); err != nil {
		t.Fatalf("preflight on a healthy path: %v", err)
	}
	if got, _ := mem.LookupTXT(ctx, DNS01RecordName("example.com")); len(got) != 0 {
		t.Errorf("preflight left a probe record behind: %v", got)
	}
}

func TestPreflightDetectsBrokenDelegation(t *testing.T) {
	ctx := context.Background()
	broken := relBrokenProvider{} // present() no-ops; the record never appears
	empty := &MemoryDNSProvider{} // the authoritative view never sees it
	c := &PropagationChecker{Resolvers: []Resolver{empty}, Interval: time.Second, Timeout: 3 * time.Second, sleep: noSleep}
	if err := PreflightDNS01(ctx, broken, c, "example.com"); err == nil {
		t.Fatal("preflight passed despite a broken DNS-01 path")
	}
}
