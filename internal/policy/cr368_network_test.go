// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCR368PolicyModulesCannotMakeNetworkRequests(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(endpoint.Close)
	lifecycle := `package trstctl.policy
default allow := false
allow if { response := http.send({"method": "GET", "url": "` + endpoint.URL + `"}); response.status_code == 200 }`
	abac := `package trstctl.abac
default deny := false
deny if { response := http.send({"method": "GET", "url": "` + endpoint.URL + `"}); response.status_code == 200 }`

	t.Run("live lifecycle", func(t *testing.T) {
		if _, err := New(Config{Module: lifecycle}); err == nil {
			t.Fatal("network builtin compiled in lifecycle policy")
		}
	})
	t.Run("tenant lifecycle", func(t *testing.T) {
		if _, err := NewLive(Config{Module: lifecycle}); err == nil {
			t.Fatal("network builtin compiled in tenant policy")
		}
	})
	t.Run("previously stored tenant policy", func(t *testing.T) {
		live, err := NewLive(Config{})
		if err != nil {
			t.Fatal(err)
		}
		info := moduleInfo(DryRunKindLifecycle, lifecycle, "trstctl.policy", "data.trstctl.policy")
		live.SetModuleResolver(func(context.Context, string) (string, ModuleInfo, error) {
			return lifecycle, info, nil
		})
		decision, err := live.Evaluate(context.Background(), Input{TenantID: "tenant-a", Action: ActionIssue})
		if err == nil || decision.Allow {
			t.Fatalf("previously stored network policy = %+v, %v; want fail closed", decision, err)
		}
	})
	t.Run("lifecycle dry run", func(t *testing.T) {
		result, err := DryRun(context.Background(), DryRunConfig{Module: lifecycle,
			Input: map[string]any{"tenant_id": "tenant-a", "action": "issue"}})
		if err != nil || result.Valid || !strings.Contains(result.Error, "http.send") {
			t.Fatalf("network dry run = %+v, %v; want compile refusal", result, err)
		}
	})
	t.Run("operator ABAC", func(t *testing.T) {
		if _, err := NewABAC(ABACConfig{Module: abac}); err == nil {
			t.Fatal("network builtin compiled in ABAC overlay")
		}
	})
	t.Run("ABAC dry run", func(t *testing.T) {
		result, err := DryRun(context.Background(), DryRunConfig{Kind: DryRunKindABAC, Module: abac,
			Input: map[string]any{"tenant_id": "tenant-a", "permission": "certs:issue"}})
		if err != nil || result.Valid || !strings.Contains(result.Error, "http.send") {
			t.Fatalf("network ABAC dry run = %+v, %v; want compile refusal", result, err)
		}
	})
	t.Run("DNS lookup", func(t *testing.T) {
		module := `package trstctl.policy
default allow := false
allow if { count(net.lookup_ip_addr("metadata.google.internal")) > 0 }`
		if _, err := New(Config{Module: module}); err == nil {
			t.Fatal("DNS builtin compiled in lifecycle policy")
		}
	})
	if got := requests.Load(); got != 0 {
		t.Fatalf("policy made %d network requests", got)
	}
}
