// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A186-L2 Done-when: a tenant template defines tenant custom roles. A
// baseline with a custom role and a member who holds it creates the role
// before the member; the member's role grants exactly the template's
// permissions; drift reads the role from the tenant's own record, so a
// customer who changes the role's permissions shows it drifted, and applying
// again redefines it; a template whose custom role takes a built-in role's
// name, or grants a permission outside the custom role vocabulary, is
// refused before it is applied anywhere.
func TestServedTenantBaselineDefinesCustomRolesA186L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.EnablePolicyGate = true })
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "provider:ops@provider.example"})
	const scope = "template-reviewers"
	baseline := api.TenantBaseline{
		CustomRoles: []api.BaselineCustomRole{{Name: "cert-reviewer", Description: "reviews certificates and discovery",
			Permissions: []string{"certs:read", "discovery:read"}}},
		Members: []api.BaselineMember{{Subject: "reviewer@customer.example", Email: "reviewer@customer.example", Roles: []string{"cert-reviewer"}}},
	}
	if err := h.srv.api.ValidateTenantBaseline(baseline); err != nil {
		t.Fatalf("a valid template = %v", err)
	}
	applied, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil || !applied.Complete || len(applied.Results) != 2 {
		t.Fatalf("apply = %+v %v", applied, err)
	}
	if first := applied.Results[0]; first.Kind != api.BaselineKindCustomRole || first.Key != "cert-reviewer" || first.Outcome != api.BaselineCreated ||
		first.Status != api.BaselineInSync {
		t.Fatalf("the custom role is not applied first: %+v", applied.Results)
	}
	role, err := h.store.GetTenantCustomRole(t.Context(), h.tenant, "cert-reviewer")
	if err != nil || role.Description != "reviews certificates and discovery" || !slices.Equal(a186l2Sorted(role.Permissions), []string{"certs:read", "discovery:read"}) {
		t.Fatalf("custom role = %+v %v", role, err)
	}
	if m, err := h.store.GetTenantMember(t.Context(), h.tenant, "reviewer@customer.example"); err != nil || len(m.Roles) != 1 || m.Roles[0] != "cert-reviewer" {
		t.Fatalf("member = %+v %v", m, err)
	}
	drift, err := h.srv.api.TenantBaselineDrift(ctx, h.tenant, scope, baseline)
	if err != nil || !drift.InSync {
		t.Fatalf("drift after apply = %+v %v", drift, err)
	}

	// The customer widens the role in their tenant: drifted, then repaired.
	if _, err := h.srv.orch.DefineTenantCustomRole(ctx, h.tenant, projections.TenantCustomRoleUpserted{Name: "cert-reviewer",
		Description: "reviews certificates and discovery", Permissions: []string{"certs:read", "discovery:read", "discovery:write"}}); err != nil {
		t.Fatal(err)
	}
	drift, err = h.srv.api.TenantBaselineDrift(ctx, h.tenant, scope, baseline)
	if err != nil || drift.InSync {
		t.Fatalf("drift after the customer's change = %+v %v", drift, err)
	}
	for _, o := range drift.Objects {
		if o.Kind == api.BaselineKindCustomRole && o.Status != api.BaselineDrifted {
			t.Fatalf("custom role state = %+v; want drifted", o)
		}
	}
	repaired, err := h.srv.api.ApplyTenantBaseline(ctx, h.tenant, scope, baseline)
	if err != nil || !repaired.Complete || repaired.Results[0].Outcome != api.BaselineUpdated {
		t.Fatalf("repair = %+v %v", repaired, err)
	}
	if role, err := h.store.GetTenantCustomRole(t.Context(), h.tenant, "cert-reviewer"); err != nil || len(role.Permissions) != 2 {
		t.Fatalf("custom role after repair = %+v %v", role, err)
	}

	for name, bad := range map[string]api.BaselineCustomRole{
		"a built-in role's name": {Name: "operator", Permissions: []string{"certs:read"}},
		"an unknown permission":  {Name: "wide-open", Permissions: []string{"everything:all"}},
		"no permission":          {Name: "empty-role"},
	} {
		if err := h.srv.api.ValidateTenantBaseline(api.TenantBaseline{CustomRoles: []api.BaselineCustomRole{bad}}); err == nil ||
			!strings.Contains(err.Error(), "baseline custom role") {
			t.Fatalf("%s = %v; want refused", name, err)
		}
	}
	if err := h.srv.api.ValidateTenantBaseline(api.TenantBaseline{CustomRoles: []api.BaselineCustomRole{
		{Name: "dup", Permissions: []string{"certs:read"}}, {Name: "dup", Permissions: []string{"certs:read"}}}}); err == nil {
		t.Fatal("a template naming one custom role twice was accepted")
	}
}

func a186l2Sorted(values []string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}
