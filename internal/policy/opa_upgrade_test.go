// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/policy"
)

func TestOPA121YAML12AndEmptyCompositeSemantics(t *testing.T) {
	const yamlModule = `package trstctl.policy
default allow := false
allow if {
  doc := yaml.unmarshal("on: yes\noff: no\nflag: true\n")
  doc["on"] == "yes"
  doc["off"] == "no"
  doc.flag == true
  object.get({}, "missing", "fallback") == "fallback"
  count([]) == 0
}`
	engine, err := policy.New(policy.Config{Module: yamlModule})
	if err != nil {
		t.Fatalf("compile YAML 1.2 tenant policy: %v", err)
	}
	decision, err := engine.Evaluate(t.Context(), policy.Input{TenantID: "tenant-a"})
	if err != nil || !decision.Allow {
		t.Fatalf("YAML 1.2 and empty-composite safe access = %+v, %v", decision, err)
	}
	for _, invalid := range []string{
		`package trstctl.policy
default allow := false
allow if { allow }`,
		`package trstctl.policy
default allow := false
allow if { obj := {}; obj.missing }`,
		`package trstctl.policy
default allow := false
allow if { some x in []; x == 1 }`,
	} {
		if _, err := policy.New(policy.Config{Module: invalid}); err == nil {
			t.Fatalf("OPA accepted recursive or invalid empty-composite tenant module: %s", invalid)
		}
	}
}

func TestOPA1211NestedComprehensionCompilerRegression(t *testing.T) {
	const module = `package trstctl.policy
default allow := false
allow if {
  grouped := {"k": [r.a | some r in input.attrs.rows]}
  grouped.k == ["expected"]
}`
	engine, err := policy.New(policy.Config{Module: module})
	if err != nil {
		t.Fatalf("OPA v1.21.1 nested-comprehension fix did not compile: %v", err)
	}
	decision, err := engine.Evaluate(t.Context(), policy.Input{
		TenantID: "tenant-a", Attrs: map[string]any{"rows": []map[string]any{{"a": "expected"}}},
	})
	if err != nil || !decision.Allow {
		t.Fatalf("nested-comprehension decision = %+v, %v", decision, err)
	}
}

func TestOPA121TenantPolicyConcurrentIsolation(t *testing.T) {
	const moduleA = `package trstctl.policy
default allow := false
allow if { input.tenant_id == "tenant-a"; input.action == "issue" }`
	const moduleB = `package trstctl.policy
default allow := false
allow if { input.tenant_id == "tenant-b"; input.action == "revoke" }`
	live, err := policy.NewLive(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, infoA, _, err := live.PrepareModule(moduleA)
	if err != nil {
		t.Fatal(err)
	}
	_, infoB, _, err := live.PrepareModule(moduleB)
	if err != nil {
		t.Fatal(err)
	}
	live.SetModuleResolver(func(_ context.Context, tenantID string) (string, policy.ModuleInfo, error) {
		switch tenantID {
		case "tenant-a":
			return moduleA, infoA, nil
		case "tenant-b":
			return moduleB, infoB, nil
		default:
			return "", policy.ModuleInfo{}, errors.New("unknown tenant")
		}
	})
	const workers = 64
	var wg sync.WaitGroup
	failures := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant, action := "tenant-a", policy.ActionIssue
			if i%2 != 0 {
				tenant, action = "tenant-b", policy.ActionRevoke
			}
			allow, err := live.Evaluate(context.Background(), policy.Input{TenantID: tenant, Action: action})
			if err != nil || !allow.Allow {
				failures <- fmt.Errorf("tenant %s allowed action %s = %+v, %v", tenant, action, allow, err)
				return
			}
			other := policy.ActionRevoke
			if action == policy.ActionRevoke {
				other = policy.ActionIssue
			}
			deny, err := live.Evaluate(context.Background(), policy.Input{TenantID: tenant, Action: other})
			if err != nil || deny.Allow {
				failures <- fmt.Errorf("tenant %s denied action %s = %+v, %v", tenant, other, deny, err)
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestOPA121CanceledQueuedEvaluationsFailClosed(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "opa-upgrade-cancellation", Workers: 1, Queue: 1})
	defer pool.Close()
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	if err := pool.Submit(func() { close(started); <-release }); err != nil {
		t.Fatal(err)
	}
	<-started
	lifecycle, err := policy.New(policy.Config{Pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		decision, err := lifecycle.Evaluate(ctx, policy.Input{TenantID: "tenant-a", Action: policy.ActionRevoke})
		if decision.Allow || !errors.Is(err, context.Canceled) {
			done <- fmt.Errorf("canceled lifecycle evaluation = %+v, %v", decision, err)
			return
		}
		done <- nil
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled lifecycle evaluation waited for an occupied worker")
	}
}

func TestOPA121CanceledQueuedABACEvaluationFailsClosed(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "opa-abac-cancellation", Workers: 1, Queue: 1})
	defer pool.Close()
	release := make(chan struct{})
	defer close(release)
	started := make(chan struct{})
	if err := pool.Submit(func() { close(started); <-release }); err != nil {
		t.Fatal(err)
	}
	<-started
	abac, err := policy.NewABAC(policy.ABACConfig{Pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		decision, err := abac.EvaluateDeny(ctx, policy.ABACInput{TenantID: "tenant-a", Permission: "certs:issue"})
		if !decision.Deny || !errors.Is(err, context.Canceled) {
			done <- fmt.Errorf("canceled ABAC evaluation = %+v, %v", decision, err)
			return
		}
		done <- nil
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled ABAC evaluation waited for an occupied worker")
	}
}
