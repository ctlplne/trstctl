// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedLifecycleAutomationPlanF6 is the red/green contract for the
// operator-facing half of F6. The scheduler already runs; this route must explain
// its exact timing, non-effects, outbox handoffs, and safe run controls without
// making the browser reconstruct policy from unrelated endpoints.
func TestServedLifecycleAutomationPlanF6(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.LifecycleInterval = 2 * time.Minute
	})
	tok := seedScopedToken(t, h.store, h.tenant, "lifecycle:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/lifecycle/automation-plan", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("lifecycle automation plan: status %d body %s", status, body)
	}
	var got struct {
		Capability string `json:"capability"`
		Ready      bool   `json:"ready"`
		Scheduler  struct {
			Status      string `json:"status"`
			RenewBefore string `json:"renew_before"`
			AlertBefore string `json:"alert_before"`
			Interval    string `json:"interval"`
			ARIFirst    bool   `json:"ari_first"`
			Maintenance string `json:"maintenance_window_status"`
		} `json:"scheduler"`
		Controls []struct {
			Action string `json:"action"`
			State  string `json:"state"`
		} `json:"controls"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		ExecutionWrites        []string `json:"execution_writes"`
		ExecutionEffects       []string `json:"execution_external_effects"`
		VerificationSteps      []string `json:"verification_steps"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode lifecycle automation plan: %v (%s)", err, body)
	}
	if got.Capability != "lifecycle_automation" || !got.Ready {
		t.Fatalf("plan identity/readiness = %q/%t, want lifecycle_automation/true", got.Capability, got.Ready)
	}
	if got.Scheduler.Status != "running" || got.Scheduler.RenewBefore != "744h0m0s" ||
		got.Scheduler.AlertBefore != "168h0m0s" || got.Scheduler.Interval != "2m0s" ||
		!got.Scheduler.ARIFirst || got.Scheduler.Maintenance != "open" {
		t.Fatalf("scheduler truth = %+v", got.Scheduler)
	}
	if len(got.PreviewWrites) != 0 || len(got.PreviewExternalEffects) != 0 {
		t.Fatalf("effect-free preview wrote or contacted something: writes=%v effects=%v", got.PreviewWrites, got.PreviewExternalEffects)
	}
	if len(got.ExecutionWrites) == 0 || len(got.ExecutionEffects) == 0 || len(got.VerificationSteps) == 0 {
		t.Fatalf("plan omits execution/verification truth: writes=%v effects=%v verify=%v", got.ExecutionWrites, got.ExecutionEffects, got.VerificationSteps)
	}
	states := map[string]string{}
	for _, control := range got.Controls {
		states[control.Action] = control.State
	}
	for action, want := range map[string]string{
		"start": "available", "pause": "configuration_only", "resume": "automatic",
		"retry": "conditional", "cancel": "unavailable_after_enqueue", "rollback": "conditional",
	} {
		if states[action] != want {
			t.Errorf("%s control state = %q, want %q (all=%v)", action, states[action], want, states)
		}
	}
}

func TestServedLifecycleAutomationPlanListsDueWorkWithoutTenantLeakage(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 31 * 24 * time.Hour
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:write", "identities:read", "identities:write", "certs:issue", "lifecycle:read",
	)
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload", "name": "payments-platform",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind": "x509_certificate", "name": "checkout.internal", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	for _, transition := range []struct{ to, reason string }{
		{to: "issued", reason: "issue lifecycle-plan fixture"},
		{to: "deployed", reason: "deploy lifecycle-plan fixture"},
	} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", tok, map[string]any{
			"to": transition.to, "reason": transition.reason,
		})
		if status != http.StatusOK {
			t.Fatalf("transition %s: status %d body %s", transition.to, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain %s: %v", transition.to, err)
		}
	}
	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, "checkout.internal")
	if err != nil || len(certs) != 1 {
		t.Fatalf("load active certificate: count=%d err=%v", len(certs), err)
	}
	cert := certs[0]
	if cert.ValidityAnchor == nil {
		t.Fatal("served issuance lost its constructor anchor")
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/lifecycle/automation-plan", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get due plan: status %d body %s", status, body)
	}
	var plan apiLifecycleAutomationPlanTestResponse
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode due plan: %v (%s)", err, body)
	}
	if plan.Summary.Monitored != 1 || plan.Summary.DueNow != 0 || len(plan.Items) != 1 || plan.Items[0].Due {
		t.Fatalf("HTTP plan immediately requeues a fresh certificate: %+v", plan)
	}
	// The public route above uses the real clock. Evaluate its same served
	// planner at the actual future renewal window without editing signed data.
	future, err := h.srv.LifecycleAutomationPlan(t.Context(), h.tenant, cert.ValidityAnchor.Add(21*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(future)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Monitored != 1 || plan.Summary.DueNow != 1 || len(plan.Items) != 1 {
		t.Fatalf("due summary/items = %+v/%+v", plan.Summary, plan.Items)
	}
	item := plan.Items[0]
	if item.IdentityID != identity.ID || item.IdentityName != "checkout.internal" || item.OwnerName != "payments-platform" || !item.Due || item.RenewalSource != "ari" {
		t.Fatalf("due item = %+v", item)
	}

	const otherTenant = "22222222-2222-4222-8222-222222222222"
	if _, err := h.store.CreateOwner(context.Background(), store.Owner{TenantID: otherTenant, Kind: store.OwnerWorkload, Name: "other-tenant"}); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	otherToken := seedScopedToken(t, h.store, otherTenant, "lifecycle:read")
	status, otherBody := secretsReq(t, h, http.MethodGet, "/api/v1/lifecycle/automation-plan", otherToken, nil)
	if status != http.StatusOK {
		t.Fatalf("get other-tenant plan: status %d body %s", status, otherBody)
	}
	var other apiLifecycleAutomationPlanTestResponse
	if err := json.Unmarshal(otherBody, &other); err != nil {
		t.Fatalf("decode other-tenant plan: %v", err)
	}
	if other.Summary.Monitored != 0 || len(other.Items) != 0 {
		t.Fatalf("other tenant observed lifecycle rows: %+v", other)
	}
}

type apiLifecycleAutomationPlanTestResponse struct {
	Summary struct {
		Monitored int `json:"monitored"`
		DueNow    int `json:"due_now"`
	} `json:"summary"`
	Items []struct {
		IdentityID    string `json:"identity_id"`
		IdentityName  string `json:"identity_name"`
		OwnerName     string `json:"owner_name"`
		Due           bool   `json:"due"`
		RenewalSource string `json:"renewal_source"`
	} `json:"items"`
}
