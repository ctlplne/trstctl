// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

// Customer role definitions and assignments stay with the customer tenant.
func TestProviderTemplateLeavesCustomerRolesWithTenant(t *testing.T) {
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
	baseline.Members = []api.BaselineMember{{Subject: "customer-admin@customer.example", Roles: []string{"payments-ops"}}}
	if _, err := NewService(Config{}).applyTemplate(ctx, Operator{}, customer, TenantTemplate{Baseline: baseline}); !errors.Is(err, ErrTemplateInvalid) {
		t.Fatalf("retained template member applied: %v", err)
	}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-custom-role",
		TemplateRequest{ID: "custom-role", Name: "Custom role customer", Baseline: baseline}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "template_invalid") {
		t.Fatalf("template member grant = %d %s", rec.Code, rec.Body.String())
	}
	baseline.Members = nil
	baseline.CustomRoles = []api.BaselineCustomRole{{Name: "payments-ops", Permissions: []string{"certs:read"}}}
	if _, err := NewService(Config{}).applyTemplate(ctx, Operator{}, customer, TenantTemplate{Baseline: baseline}); !errors.Is(err, ErrTemplateInvalid) {
		t.Fatalf("retained template role definition applied: %v", err)
	}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-role-definition",
		TemplateRequest{ID: "custom-role", Name: "Custom role customer", Baseline: baseline}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "template_invalid") {
		t.Fatalf("template role definition = %d %s", rec.Code, rec.Body.String())
	}
	if versions, err := NewPGStore(st).TenantTemplateVersions(ctx, "custom-role"); err != nil || len(versions) != 0 {
		t.Fatalf("customer authority template was recorded: %d versions, %v", len(versions), err)
	}
	if m, err := st.GetTenantMember(ctx, customer, "customer-admin@customer.example"); err == nil {
		t.Fatalf("the customer gained an unapproved template member: %+v", m)
	}
}
