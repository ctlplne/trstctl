// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"os"
	"testing"
)

func TestConsoleGitOpsEnvelopeDryRunUsesABACDecision(t *testing.T) {
	module, err := os.ReadFile("../../web/src/policies/gitops-validation.rego")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"tenant_id":        "task-tenant",
		"action":           "gitops.validate",
		"permission":       "gitops:apply",
		"declaration_kind": "TrstctlProfile",
		"declaration": map[string]any{
			"apiVersion": "trstctl.com/v1",
			"kind":       "TrstctlProfile",
			"metadata":   map[string]any{"name": "task-profile"},
			"spec":       map[string]any{"active": true},
		},
	}
	allowed, err := DryRun(context.Background(), DryRunConfig{Kind: DryRunKindABAC, Module: string(module), Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Valid || !allowed.Allow || allowed.Deny || allowed.Query != "data.trstctl.abac" {
		t.Fatalf("expected applicable allow from console module, got %+v", allowed)
	}

	input["declaration"] = map[string]any{
		"apiVersion": "trstctl.com/v1",
		"kind":       "TrstctlProfile",
		"metadata":   map[string]any{"name": ""},
		"spec":       map[string]any{"active": true},
	}
	denied, err := DryRun(context.Background(), DryRunConfig{Kind: DryRunKindABAC, Module: string(module), Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !denied.Valid || !denied.Deny || denied.Allow || denied.Reason == "" {
		t.Fatalf("expected reasoned denial for incomplete envelope, got %+v", denied)
	}

	input["declaration_kind"] = "TrstctlInstallInventory"
	input["declaration"] = map[string]any{
		"apiVersion": "trstctl.com/v1",
		"kind":       "TrstctlInstallInventory",
		"metadata":   map[string]any{"name": "trstctl-control-plane"},
		"spec":       map[string]any{"chart": "deploy/helm/trstctl"},
	}
	inventory, err := DryRun(context.Background(), DryRunConfig{Kind: DryRunKindABAC, Module: string(module), Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !inventory.Valid || !inventory.Allow || inventory.Deny {
		t.Fatalf("expected inventory preview envelope allow, got %+v", inventory)
	}
	input["declaration_kind"] = "TrstctlInstallValues"
	input["declaration"].(map[string]any)["kind"] = "TrstctlInstallValues"
	obsolete, err := DryRun(context.Background(), DryRunConfig{Kind: DryRunKindABAC, Module: string(module), Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if !obsolete.Valid || !obsolete.Deny || obsolete.Allow {
		t.Fatalf("old install-values envelope must not imply a deployable file, got %+v", obsolete)
	}
}
