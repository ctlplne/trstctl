package policy

import (
	"context"
	"strings"
	"testing"
)

func TestDryRunLifecycleReturnsAllowDenyTrace(t *testing.T) {
	result, err := DryRun(context.Background(), DryRunConfig{
		Kind: DryRunKindLifecycle,
		Input: map[string]any{
			"tenant_id": "tenant-a",
			"action":    "issue",
			"profile":   "tls-server",
			"actor":     "ra@example.test",
		},
		TraceLimit: 12,
	})
	if err != nil {
		t.Fatalf("dry-run lifecycle: %v", err)
	}
	if !result.Valid || !result.Allow || result.Deny || result.ModuleSHA256 == "" {
		t.Fatalf("lifecycle result = %+v, want valid allow with module digest", result)
	}
	if len(result.Trace) == 0 {
		t.Fatal("dry-run trace is empty")
	}
	for _, row := range result.Trace {
		if strings.Contains(row.Node, "tls-server") || strings.Contains(row.Node, "ra@example.test") {
			t.Fatalf("trace row leaked plugged input values: %+v", row)
		}
	}
}

func TestDryRunABACAndCompileErrorAreFirstClassResults(t *testing.T) {
	abac, err := DryRun(context.Background(), DryRunConfig{
		Kind: DryRunKindABAC,
		Module: `package trstctl.abac

default deny := false
default reason := ""

deny if {
	input.permission == "certs:issue"
	input.actor_attrs.emergency != "true"
}

reason := "issuer requires emergency attribute" if {
	input.permission == "certs:issue"
	input.actor_attrs.emergency != "true"
}`,
		Input: map[string]any{
			"tenant_id":   "tenant-a",
			"permission":  "certs:issue",
			"actor":       "ra@example.test",
			"actor_attrs": map[string]string{"emergency": "false"},
		},
	})
	if err != nil {
		t.Fatalf("dry-run abac: %v", err)
	}
	if !abac.Valid || !abac.Deny || abac.Allow || abac.Reason != "issuer requires emergency attribute" {
		t.Fatalf("abac result = %+v, want valid deny with reason", abac)
	}

	bad, err := DryRun(context.Background(), DryRunConfig{
		Kind:   DryRunKindLifecycle,
		Module: `package trstctl.policy allow if {`,
		Input: map[string]any{
			"tenant_id": "tenant-a",
			"action":    "revoke",
		},
	})
	if err != nil {
		t.Fatalf("compile-error dry-run returned transport error: %v", err)
	}
	if bad.Valid || bad.Error == "" || !strings.Contains(bad.Error, "compile") {
		t.Fatalf("compile-error result = %+v, want invalid result with error", bad)
	}
}
