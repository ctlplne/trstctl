// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

func tenantBaselineFixture(t *testing.T) api.TenantBaseline {
	t.Helper()
	now := time.Now().UTC()
	der, err := certtest.TLSLeaf("Provider Issuing CA", now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	return api.TenantBaseline{
		Profiles: []api.BaselineProfile{{Name: "web-server", Spec: json.RawMessage(`{"allowed_key_algorithms":["ECDSA"],"allowed_protocols":["acme"],"max_validity":"720h"}`)}},
		Policy: &api.BaselinePolicy{Module: policy.BaseModule + `
certificate_posture contains {"rule": "baseline-short-lived", "severity": "low", "reason": "baseline rule"} if {
	input.action == "certificate_posture"
	input.certificate.issuer == "CN=Baseline Example CA"
}
`, Description: "provider baseline policy"},
		Issuers: []api.BaselineIssuer{{Key: "provider-ca", Name: "Provider Issuing CA", Kind: string(store.IssuerX509CA),
			Chain: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}},
		DeploymentTargets: []api.BaselineDeploymentTarget{{Key: "edge-lb", Name: "edge-lb", Connector: "f5",
			Config: json.RawMessage(`{"address_ref":"edge-lb"}`), Enabled: &disabled}},
		NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", EndpointURL: "https://hooks.example.com/trstctl"}},
		Members:              []api.BaselineMember{{Subject: "customer-admin@customer.example", Email: "customer-admin@customer.example", Roles: []string{"operator"}}},
		ReportSchedules: []api.BaselineReportSchedule{{Key: "weekly-risk", Name: "weekly crypto risk", Framework: "nist-800-53",
			ReportType: "crypto_risk", IntervalSeconds: 7 * 24 * 3600}},
	}
}

// TestServedTenantBaselineAppliesAndReportsDrift proves the tenant baseline:
// applying it creates every object through the operator's own commands, a
// second apply changes nothing, an operator's change to an object reads as
// drift on exactly that object, and applying again restores it.
func TestServedTenantBaselineAppliesAndReportsDrift(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	archiveRoot := t.TempDir()
	// #nosec G302 -- owner execute is required to traverse this private test directory.
	if err := os.Chmod(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.AuditArchiveDir = archiveRoot
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(&reportWorkerSigner{key: key}))
	})
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "provider:ops@provider.example"})
	baseline := tenantBaselineFixture(t)
	const scope = "template-standard"

	if _, err := h.srv.api.ApplyTenantBaseline(ctx, "77777777-7777-4777-8777-777777777777", scope, baseline); err == nil {
		t.Fatal("a baseline applied to a tenant core never registered")
	}
	applied, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Complete || len(applied.Results) != 7 {
		t.Fatalf("first apply = %+v", applied)
	}
	for _, r := range applied.Results {
		want := api.BaselineCreated
		if r.Kind == api.BaselineKindPolicy {
			want = api.BaselineUpdated // the baseline's module replaces the boot policy
		}
		if r.Outcome != want || r.Status != api.BaselineInSync {
			t.Fatalf("%s %s: outcome %s status %s (%s)", r.Kind, r.Key, r.Outcome, r.Status, r.Error)
		}
	}
	// Each object reads back from the tenant's own records.
	if p, err := h.store.GetActiveProfile(t.Context(), h.tenant, "web-server"); err != nil || p.Version != 1 {
		t.Fatalf("profile = %+v %v", p, err)
	}
	if m, err := h.store.GetTenantMember(t.Context(), h.tenant, "customer-admin@customer.example"); err != nil || len(m.Roles) != 1 || m.Roles[0] != "operator" {
		t.Fatalf("member = %+v %v", m, err)
	}
	if c, err := h.store.GetNotificationChannel(t.Context(), h.tenant, "webhook"); err != nil || c.EndpointURL != "https://hooks.example.com/trstctl" {
		t.Fatalf("channel = %+v %v", c, err)
	}
	drift, err := h.srv.api.TenantBaselineDrift(ctx, h.tenant, scope, baseline)
	if err != nil || !drift.InSync || len(drift.Objects) != 7 {
		t.Fatalf("drift after apply = %+v %v", drift, err)
	}

	again, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range again.Results {
		if r.Outcome != api.BaselineUnchanged {
			t.Fatalf("a second apply changed %s %s: %s", r.Kind, r.Key, r.Outcome)
		}
	}
	if p, _ := h.store.GetActiveProfile(t.Context(), h.tenant, "web-server"); p.Version != 1 {
		t.Fatalf("a second apply added profile version %d", p.Version)
	}

	// An operator changes the member's roles through the API.
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "tenant-admin@customer.example", "*")
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/members/customer-admin@customer.example", admin,
		"baseline-member-change", map[string]any{"roles": []string{"viewer"}}); status != http.StatusOK {
		t.Fatalf("operator member change = %d %s", status, body)
	}
	drift, err = h.srv.api.TenantBaselineDrift(ctx, h.tenant, scope, baseline)
	if err != nil || drift.InSync {
		t.Fatalf("drift after an operator change = %+v %v", drift, err)
	}
	for _, o := range drift.Objects {
		want := api.BaselineInSync
		if o.Kind == api.BaselineKindMember {
			want = api.BaselineDrifted
		}
		if o.Status != want {
			t.Fatalf("%s %s = %s, want %s", o.Kind, o.Key, o.Status, want)
		}
	}
	repaired, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil || !repaired.Complete {
		t.Fatalf("repair = %+v %v", repaired, err)
	}
	for _, r := range repaired.Results {
		want := api.BaselineUnchanged
		if r.Kind == api.BaselineKindMember {
			want = api.BaselineUpdated
		}
		if r.Outcome != want || r.Status != api.BaselineInSync {
			t.Fatalf("repair %s %s = %s/%s, want %s", r.Kind, r.Key, r.Outcome, r.Status, want)
		}
	}
	if !h.logContains(t, "granted by a tenant baseline") {
		t.Fatal("the baseline's role grant was not recorded as an authorization decision")
	}
}
