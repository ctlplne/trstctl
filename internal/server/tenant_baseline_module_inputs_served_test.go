// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A248-L1: a tenant baseline's connector targets are checked against the
// module's setup inputs exactly as an operator's create is (A242). The
// baseline step skipped the check, so a baseline wrote a module target with a
// required input missing, or with a secret input holding the secret itself.
func TestServedTenantBaselineChecksModuleTargetInputsA248L1(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"}, func(*Deps) {})
	reportPartnerModules(t, h)
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "provider:ops@provider.example"})
	target := func(key, config string) api.BaselineDeploymentTarget {
		return api.BaselineDeploymentTarget{Key: key, Name: "lb/" + key, Connector: "partner-lb", Config: json.RawMessage(config)}
	}
	baseline := api.TenantBaseline{DeploymentTargets: []api.BaselineDeploymentTarget{
		target("missing-partition", `{"endpoint":"https://lb.internal"}`),
		target("secret-value", `{"partition":"edge","admin_ref":"hunter2"}`),
		target("wrong-type", `{"partition":"edge","port":"443"}`),
		target("complete", `{"partition":"edge","admin_ref":"secret://lb-admin","port":8443}`),
	}}
	const scope = "a248-l1"
	applied, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"missing-partition": "setup input partition is required",
		"secret-value":      "give a reference",
		"wrong-type":        "must be an integer",
	}
	if applied.Complete || len(applied.Results) != len(baseline.DeploymentTargets) {
		t.Fatalf("apply = %+v", applied)
	}
	for _, r := range applied.Results {
		if strings.Contains(r.Error, "hunter2") {
			t.Fatalf("the refusal echoed a secret value: %s", r.Error)
		}
		got, err := h.store.GetDeploymentTarget(t.Context(), h.tenant, r.ObjectID)
		if says, refused := want[r.Key]; refused {
			if r.Outcome != api.BaselineFailed || !strings.Contains(r.Error, says) {
				t.Errorf("%s: outcome %s error %q, want failed with %q", r.Key, r.Outcome, r.Error, says)
			}
			if !store.IsNotFound(err) {
				t.Errorf("%s: the refused target was written: %+v %v", r.Key, got, err)
			}
			continue
		}
		if r.Outcome != api.BaselineCreated || err != nil || got.Type != "partner-lb" {
			t.Errorf("%s: outcome %s (%s), target %+v %v", r.Key, r.Outcome, r.Error, got, err)
		}
	}
}
