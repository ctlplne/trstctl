// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
)

func TestRotationPlanFreezesEveryReviewedNativeDependentA267(t *testing.T) {
	intent := inventoryFixtureIntent(t)
	report := inventoryFixtureReport(t)
	observed := time.Now().UTC()
	report.ObservedAt = observed
	input := RotationHostInput{Binding: intent.Binding, Inventory: report, InventoryDigest: strings.Repeat("a", 64)}
	// A stopped service and a stopped pool remain stopped; a task can run only
	// through the separately approved exact task path.
	input.Inventory.Services = append(input.Inventory.Services, windependents.Service{Name: "owned-stopped", AccountSID: intent.Binding.Account.SID, ConfigSHA256: strings.Repeat("e", 64), WasRunning: false})
	input.Inventory.Services[0].WasRunning = true
	input.Inventory.Pools[0].WasStarted = true
	input.InventoryDigest = rotationTestDigestA267(t, input.Inventory)
	requested := []DependentRef{{AgentID: intent.Binding.AgentID, Family: "services", Name: "orders"}, {AgentID: intent.Binding.AgentID, Family: "tasks", Name: "\\owned\\work"}, {AgentID: intent.Binding.AgentID, Family: "iis", Name: "orders-pool"}, {AgentID: intent.Binding.AgentID, Family: "services", Name: "owned-stopped"}}
	plan, err := NewRotationPlan("57100000-0000-4000-8000-000000000001", intent.Binding.Account, "service-secret", []RotationHostInput{input}, requested, observed)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Order) != 4 || len(plan.Hosts) != 1 || plan.SecretName != "service-secret" {
		t.Fatal("reviewed native order or source identity lost")
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Account.SID = "S-1-5-21-1-2-3-1002"
	if changed.Validate() == nil {
		t.Fatal("rotation plan accepted another directory authority")
	}
	partial := input
	partial.Inventory.Coverage = []FamilyCoverage{{Family: "services", Status: "complete"}, {Family: "tasks", Status: "complete"}, {Family: "iis", Status: "unavailable", Failure: "native_read_failed"}}
	partial.Inventory.Pools = nil
	partial.InventoryDigest = rotationTestDigestA267(t, partial.Inventory)
	if _, err := NewRotationPlan(plan.ID, intent.Binding.Account, "service-secret", []RotationHostInput{partial}, requested, observed); err == nil {
		t.Fatal("unknown native family was silently excluded before directory reset")
	}
	if _, err := NewRotationPlan(plan.ID, intent.Binding.Account, "service-secret", []RotationHostInput{input}, requested[:3], observed); err == nil {
		t.Fatal("review omitted a discovered dependent")
	}
	stale := input
	stale.Inventory.ObservedAt = observed.Add(-16 * time.Minute)
	stale.InventoryDigest = rotationTestDigestA267(t, stale.Inventory)
	if _, err := NewRotationPlan(plan.ID, intent.Binding.Account, "service-secret", []RotationHostInput{stale}, requested, observed); err == nil {
		t.Fatal("stale native inventory authorized a password reset")
	}
	foreign := input
	foreign.Binding.Revision++
	if _, err := NewRotationPlan(plan.ID, intent.Binding.Account, "service-secret", []RotationHostInput{foreign}, requested, observed); err == nil {
		t.Fatal("rebound host borrowed an older inventory")
	}
}

func rotationTestDigestA267(t *testing.T, report InventoryReport) string {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.SHA256Hex(raw)
}
