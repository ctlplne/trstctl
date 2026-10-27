// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/server"
	corestore "trstctl.com/trstctl/internal/store"
)

const templateOperatorCredential = "Bearer template-operator"

var templateDatabaseID atomic.Int64

// isolatedTemplateFixture opens a store on a database of its own in the
// package's embedded cluster, with a fresh event log. An assembled server checks
// its store against its log, so it cannot share the package database that other
// tests' logs wrote.
func isolatedTemplateFixture(t *testing.T) (*corestore.Store, *events.Log, *EventMutationSink) {
	t.Helper()
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, providerTestDSN)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("provider_templates_%d_%d", os.Getpid(), templateDatabaseID.Add(1))
	_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	_ = conn.Close(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st, err := corestore.Open(ctx, strings.TrimSuffix(providerTestDSN, "/postgres")+"/"+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return st, log, NewEventMutationSink(log, NewAuthorityProjection(st))
}

func templateRequest(t *testing.T, h http.Handler, method, path, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", templateOperatorCredential)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func templateBaseline(channelLabel string) api.TenantBaseline {
	return api.TenantBaseline{
		Profiles: []api.BaselineProfile{{Name: "web-server", Spec: json.RawMessage(`{"allowed_key_algorithms":["ECDSA"],"allowed_protocols":["acme"],"max_validity":"720h"}`)}},
		Policy: &api.BaselinePolicy{Module: policy.BaseModule + `
certificate_posture contains {"rule": "provider-template", "severity": "low", "reason": "template rule"} if {
	input.action == "certificate_posture"
	input.certificate.issuer == "CN=Template Example CA"
}
`},
		Issuers: []api.BaselineIssuer{{Key: "provider-ca", Name: "Provider Issuing CA", Kind: string(corestore.IssuerX509CA),
			Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}}},
		DeploymentTargets: []api.BaselineDeploymentTarget{{Key: "edge-lb", Name: "edge-lb", Connector: "f5",
			Config: json.RawMessage(`{"address_ref":"edge-lb"}`)}},
		NotificationChannels: []api.BaselineNotificationChannel{{ChannelType: "webhook", Label: channelLabel, EndpointURL: "https://hooks.example.com/trstctl"}},
		Members:              []api.BaselineMember{{Subject: "customer-admin@customer.example", Roles: []string{"operator"}}},
	}
}

// TestProviderTemplatesOnboardDriftAndRollout drives tenant templates through
// the Provider handler against the assembled server's tenant baseline: a
// customer onboarded from a template holds every templated object (its core
// tenant registered on the way), an operator's change in the customer reads as
// drift, a new version previews per customer, a rollout against a stale preview
// is refused, and the rollout applies, each application an audited event.
func TestProviderTemplatesOnboardDriftAndRollout(t *testing.T) {
	ctx := t.Context()
	st, log, sink := isolatedTemplateFixture(t)
	customer := CustomerID("template-customer")
	other := CustomerID("template-other")
	delegations := StaticDelegations{
		{OperatorID: "op-1", CustomerID: customer, Operations: []Operation{OpRead, OpProvision}},
	}
	var orch *orchestrator.Orchestrator
	srv, err := server.Build(ctx, server.Deps{Store: st, Log: log, EnablePolicyGate: true,
		ProviderHandlerFactory: func(o *orchestrator.Orchestrator, baselines api.ProviderTenantServices) (http.Handler, error) {
			orch = o
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

	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants", "provision-customer",
		ProvisionRequest{Slug: "template-customer", Name: "Template Customer"}); rec.Code != http.StatusCreated {
		t.Fatalf("provision = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.GetTenant(ctx, customer); err == nil {
		t.Fatal("the customer's core tenant existed before onboarding; the test would not prove registration")
	}

	// Recording validates with core's own checks.
	bad := templateBaseline("Ops")
	bad.Members[0].Roles = []string{"no-such-role"}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-bad",
		TemplateRequest{ID: "standard", Name: "Standard customer", Baseline: bad}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "template_invalid") {
		t.Fatalf("invalid template = %d %s", rec.Code, rec.Body.String())
	}
	rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-v1",
		TemplateRequest{ID: "standard", Name: "Standard customer", Baseline: templateBaseline("Ops")})
	var v1 TenantTemplate
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v1) != nil || v1.Version != 1 || v1.Digest == "" {
		t.Fatalf("record v1 = %d %s", rec.Code, rec.Body.String())
	}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-v1-again",
		TemplateRequest{ID: "standard", Name: "Standard customer", Baseline: templateBaseline("Ops")}); !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Fatalf("an unchanged template minted a version: %s", rec.Body.String())
	}

	// Onboard: the customer's core tenant is registered and every object written.
	rec = templateRequest(t, h, http.MethodPost, "/provider/v1/tenants/"+customer+"/template", "onboard",
		TemplateApplyRequest{TemplateID: "standard"})
	var onboarded TemplateApplication
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &onboarded) != nil || !onboarded.Complete || len(onboarded.Results) != 6 {
		t.Fatalf("onboard = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := st.GetTenant(ctx, customer); err != nil {
		t.Fatalf("onboarding did not register the customer's tenant: %v", err)
	}
	if m, err := st.GetTenantMember(ctx, customer, "customer-admin@customer.example"); err != nil || len(m.Roles) != 1 || m.Roles[0] != "operator" {
		t.Fatalf("templated member = %+v %v", m, err)
	}
	if p, err := st.GetActiveProfile(ctx, customer, "web-server"); err != nil || p.Version != 1 {
		t.Fatalf("templated profile = %+v %v", p, err)
	}
	drift := func() TemplateDrift {
		t.Helper()
		rec := templateRequest(t, h, http.MethodGet, "/provider/v1/tenants/"+customer+"/template-drift", "", nil)
		var d TemplateDrift
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
			t.Fatalf("drift = %d %s", rec.Code, rec.Body.String())
		}
		return d
	}
	if d := drift(); !d.Report.InSync || d.Binding.Version != 1 || d.LatestVersion != 1 {
		t.Fatalf("drift after onboarding = %+v", d)
	}

	// The customer's own administrator changes the member's roles.
	if _, err := orch.UpsertTenantMember(ctx, customer, corestore.TenantMember{Subject: "customer-admin@customer.example", Roles: []string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	d := drift()
	drifted := map[string]string{}
	for _, o := range d.Report.Objects {
		if o.Status != api.BaselineInSync {
			drifted[o.Kind] = o.Status
		}
	}
	if d.Report.InSync || len(drifted) != 1 || drifted[api.BaselineKindMember] != api.BaselineDrifted {
		t.Fatalf("drift after a customer change = %v", drifted)
	}

	// Version 2 renames the notification channel; preview, a stale rollout, the rollout.
	rec = templateRequest(t, h, http.MethodPost, "/provider/v1/templates", "record-v2",
		TemplateRequest{ID: "standard", Name: "Standard customer", Baseline: templateBaseline("Operations on call")})
	var v2 TenantTemplate
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v2) != nil || v2.Version != 2 {
		t.Fatalf("record v2 = %d %s", rec.Code, rec.Body.String())
	}
	rec = templateRequest(t, h, http.MethodPost, "/provider/v1/templates/standard/rollout/preview", "preview-v2", RolloutRequest{})
	var preview RolloutPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &preview) != nil || preview.Version != 2 || len(preview.Tenants) != 1 {
		t.Fatalf("preview = %d %s", rec.Code, rec.Body.String())
	}
	changes := map[string]bool{}
	for _, c := range preview.Tenants[0].Changes {
		changes[c.Kind] = true
	}
	if preview.Tenants[0].TenantID != customer || preview.Tenants[0].CurrentVersion != 1 || len(changes) != 2 ||
		!changes[api.BaselineKindNotificationChannel] || !changes[api.BaselineKindMember] {
		t.Fatalf("preview changes = %+v", preview.Tenants[0])
	}
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/templates/standard/rollout", "rollout-stale",
		RolloutRequest{PreviewFingerprint: "stale"}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "template_rollout_stale") {
		t.Fatalf("stale rollout = %d %s", rec.Code, rec.Body.String())
	}
	rec = templateRequest(t, h, http.MethodPost, "/provider/v1/templates/standard/rollout", "rollout-v2",
		RolloutRequest{PreviewFingerprint: preview.Fingerprint})
	var rolled RolloutResult
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rolled) != nil || len(rolled.Applications) != 1 || !rolled.Applications[0].Complete {
		t.Fatalf("rollout = %d %s", rec.Code, rec.Body.String())
	}
	if d := drift(); !d.Report.InSync || d.Binding.Version != 2 {
		t.Fatalf("drift after the rollout = %+v", d)
	}
	if c, err := st.GetNotificationChannel(ctx, customer, "webhook"); err != nil || c.Label != "Operations on call" {
		t.Fatalf("rolled-out channel = %+v %v", c, err)
	}

	// Every application is an audited Provider event naming the operator.
	activity := templateRequest(t, h, http.MethodGet, "/provider/v1/activity", "", nil)
	if activity.Code != http.StatusOK || strings.Count(activity.Body.String(), EventTenantTemplateApplied) != 2 ||
		!strings.Contains(activity.Body.String(), EventTemplateRecorded) {
		t.Fatalf("activity = %d %s", activity.Code, activity.Body.String())
	}

	// Outside the operator's delegation, nothing is applied or read.
	if rec := templateRequest(t, h, http.MethodPost, "/provider/v1/tenants/"+other+"/template", "onboard-other",
		TemplateApplyRequest{TemplateID: "standard"}); rec.Code != http.StatusForbidden {
		t.Fatalf("an undelegated customer was onboarded: %d %s", rec.Code, rec.Body.String())
	}
	if rec := templateRequest(t, h, http.MethodGet, "/provider/v1/tenants/"+other+"/template-drift", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("an undelegated customer's drift was read: %d", rec.Code)
	}
}
