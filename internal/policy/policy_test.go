package policy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/policy"
)

func newEngine(t *testing.T, pool *bulkhead.Pool) *policy.Engine {
	t.Helper()
	e, err := policy.New(policy.Config{Module: policy.BaseModule, Pool: pool})
	if err != nil {
		t.Fatalf("compile base policy: %v", err)
	}
	return e
}

func TestAllowsIssueWithProfile(t *testing.T) {
	e := newEngine(t, nil)
	d, err := e.Evaluate(context.Background(), policy.Input{Action: policy.ActionIssue, TenantID: "t1", Profile: "tls-server"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !d.Allow {
		t.Errorf("issue with a bound profile should be allowed, got deny: %q", d.Reason)
	}
}

func TestDeniesIssueWithoutProfile(t *testing.T) {
	e := newEngine(t, nil)
	d, _ := e.Evaluate(context.Background(), policy.Input{Action: policy.ActionIssue, TenantID: "t1"})
	if d.Allow {
		t.Fatal("issue without a profile must be denied")
	}
	if !strings.Contains(d.Reason, "profile") {
		t.Errorf("deny reason should mention the missing profile, got %q", d.Reason)
	}
}

func TestAllowsRevoke(t *testing.T) {
	e := newEngine(t, nil)
	d, _ := e.Evaluate(context.Background(), policy.Input{Action: policy.ActionRevoke, TenantID: "t1"})
	if !d.Allow {
		t.Errorf("revoke should be allowed by the base policy, got deny: %q", d.Reason)
	}
}

func TestDefaultDenyUnknownAction(t *testing.T) {
	e := newEngine(t, nil)
	d, _ := e.Evaluate(context.Background(), policy.Input{Action: "frobnicate", TenantID: "t1", Profile: "x"})
	if d.Allow {
		t.Fatal("an unrecognized action must be default-denied")
	}
}

func TestInvalidModuleFailsClosed(t *testing.T) {
	if _, err := policy.New(policy.Config{Module: "this is not valid rego {{{"}); err == nil {
		t.Fatal("a non-compiling policy module must be a hard error, not a silent allow")
	}
}

// TestBulkheadSheds: with the single worker occupied and no queue, a policy evaluation
// is rejected fast (fail closed) rather than blocking the caller (AN-7).
func TestBulkheadSheds(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "policy", Workers: 1, Queue: 0})
	defer pool.Close()

	release := make(chan struct{})
	occupied := make(chan struct{})
	// With Queue:0 the handoff is synchronous, so retry until the worker goroutine is
	// parked and accepts the occupying task.
	for {
		if err := pool.Submit(func() { close(occupied); <-release }); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	<-occupied // the single worker is now busy

	e := newEngine(t, pool)
	d, err := e.Evaluate(context.Background(), policy.Input{Action: policy.ActionRevoke, TenantID: "t1"})
	if err == nil {
		t.Fatal("evaluation under saturation should be rejected")
	}
	if d.Allow {
		t.Error("a shed decision must fail closed (deny)")
	}
	close(release)
}
