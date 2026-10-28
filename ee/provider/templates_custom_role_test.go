// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

// A template may name a tenant custom role. Recording it checks only that the
// name is well formed, since no tenant is bound; applying it to a tenant that
// has not defined the role fails that member with the reason, and the tenant
// gains no member holding a role that grants nothing.
func TestProviderTemplateNamingAnUndefinedCustomRoleFailsWhenApplied(t *testing.T) {
	ctx := t.Context()
	st, log, sink := isolatedTemplateFixture(t)
	customer := CustomerID("template-custom-role")
	delegations := StaticDelegations{
		{OperatorID: "op-1", CustomerID: customer, Operations: []Operation{OpRead, OpProvision}},
	}
	srv, err := server.Build(ctx, server.Deps{Store: st, Log: log, EnablePolicyGate: true,
		ProviderHandlerFactory: func(o *orchestrator.Orchestrator, baselines api.ProviderTenantServices) (http.Handler, error) {
			return NewHandler(Config{
				License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: sink, Activity: NewEventLogActivitySource(log),
				Authenticator: stubAuth{accept: templateOperatorCredential}, Delegations: delegations,
				Templates: TemplateDeps{Store: NewPGStore(st), Baselines: baselines, RegisterTenant: o.RegisterTenant},
			}), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	h := srv.Handler()
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants", "provision-custom-role",
		ProvisionRequest{Slug: "template-custom-role", Name: "Template Custom Role"}); rec.Code != http.StatusCreated {
		t.Fatalf("provision = %d %s", rec.Code, rec.Body.String())
	}
	baseline := templateBaseline("Ops")
	baseline.Members[0].Roles = []string{"payments-ops"}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-custom-role",
		TemplateRequest{ID: "custom-role", Name: "Custom role customer", Baseline: baseline}); rec.Code != http.StatusOK {
		t.Fatalf("a template naming a well-formed custom role was refused: %d %s", rec.Code, rec.Body.String())
	}
	rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants/"+customer+"/template", "onboard-custom-role",
		TemplateApplyRequest{TemplateID: "custom-role"})
	var applied TemplateApplication
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &applied) != nil || applied.Complete {
		t.Fatalf("onboarding with an undefined custom role = %d %s", rec.Code, rec.Body.String())
	}
	var member *api.BaselineObjectResult
	for i := range applied.Results {
		if applied.Results[i].Kind == api.BaselineKindMember {
			member = &applied.Results[i]
		}
	}
	if member == nil || member.Outcome != api.BaselineFailed || !strings.Contains(member.Error, "unknown role payments-ops") {
		t.Fatalf("member result = %+v", member)
	}
	if m, err := st.GetTenantMember(ctx, customer, "customer-admin@customer.example"); err == nil {
		t.Fatalf("the tenant gained a member holding an undefined role: %+v", m)
	}
}
