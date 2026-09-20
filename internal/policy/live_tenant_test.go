// SPDX-License-Identifier: BUSL-1.1

package policy_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/policy"
)

func TestLiveTenantResolverFailsClosedAndDoesNotMixConcurrentDecisions(t *testing.T) {
	live, err := policy.NewLive(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, denyInfo, deny, err := live.PrepareModule("package trstctl.policy\ndefault allow := false\ndefault reason := \"tenant A freeze\"")
	if err != nil {
		t.Fatal(err)
	}
	boot, bootInfo := live.BootModule()
	live.SetModuleResolver(func(_ context.Context, tenant string) (string, policy.ModuleInfo, error) {
		switch tenant {
		case "A":
			return deny, denyInfo, nil
		case "B":
			return boot, bootInfo, nil
		case "unreadable":
			return "", policy.ModuleInfo{}, errors.New("event log unavailable")
		case "tampered":
			return deny, bootInfo, nil
		default:
			return "", policy.ModuleInfo{}, errors.New("unknown tenant")
		}
	})
	var wg sync.WaitGroup
	for range 20 {
		for _, tenant := range []string{"A", "B", "unreadable", "tampered", ""} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d, err := live.Evaluate(context.Background(), policy.Input{Action: policy.ActionIssue, TenantID: tenant, Profile: "tls"})
				want := tenant == "B"
				if d.Allow != want {
					t.Errorf("%s allow=%v want %v", tenant, d.Allow, want)
				}
				if (tenant == "unreadable" || tenant == "tampered" || tenant == "") && err == nil {
					t.Errorf("%s silently accepted unavailable authority", tenant)
				}
			}()
		}
	}
	wg.Wait()
}
