// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenancy"
)

// A96: the Provider assurance console reads, per delegated customer, the
// isolation the deployment actually gives it: the isolation model, the
// PostgreSQL schema, the JetStream lane, the object-key prefix and whether the
// customer's audit stream exists and holds events. It is a read under the
// customer's read delegation; a pooled customer says so rather than inventing
// targets, and an operator without the customer's read grant sees nothing.
type fakeAuditStreams struct {
	streams map[string]events.TenantAuditStream
}

func (f fakeAuditStreams) TenantAuditStreamInfo(_ context.Context, lane string) (events.TenantAuditStream, error) {
	return f.streams[lane], nil
}

type siloRouterStub struct{ targets map[string]tenancy.Targets }

func (r siloRouterStub) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	if t, ok := r.targets[tenantID]; ok {
		return t, nil
	}
	return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
}

func (r siloRouterStub) JetStreamSubjectLanes(context.Context) ([]string, error) { return nil, nil }

func TestProviderAssuranceReadsCustomerIsolationA96(t *testing.T) {
	previous := tenancy.CurrentRouter()
	tenancy.SetRouter(siloRouterStub{targets: map[string]tenancy.Targets{
		"tenant-x": {Model: tenancy.IsolationSiloed, PostgresSchema: "tenant_x", JetStreamSubjectLane: "x-lane", ObjectKeyPrefix: "silo/x/"},
	}})
	t.Cleanup(func() { tenancy.SetRouter(previous) })
	store := NewMemStore()
	for _, id := range []string{"tenant-x", "tenant-y"} {
		if _, err := store.CreateTenant(context.Background(), Tenant{ID: id, Slug: id, Name: id, Status: TenantActive}); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewService(Config{
		License: providerLicense(t, 10), Store: store, Clock: fixedClock(),
		Delegations:  append(fullyDelegated("op-1", "tenant-x"), Delegation{OperatorID: "op-1", CustomerID: "tenant-y", Operations: []Operation{OpRead}}),
		AuditStreams: fakeAuditStreams{streams: map[string]events.TenantAuditStream{"x-lane": {Name: "TRSTCTL_AUDIT_x-lane", Lane: "x-lane", Exists: true, Messages: 12}}},
	})
	h := NewHandler(Config{License: providerLicense(t, 10), Store: store, Clock: fixedClock(), Authenticator: stubAuth{accept: "Bearer a96"},
		Delegations:  append(fullyDelegated("op-1", "tenant-x"), Delegation{OperatorID: "op-1", CustomerID: "tenant-y", Operations: []Operation{OpRead}}),
		AuditStreams: fakeAuditStreams{streams: map[string]events.TenantAuditStream{"x-lane": {Name: "TRSTCTL_AUDIT_x-lane", Lane: "x-lane", Exists: true, Messages: 12}}}})

	siloed, err := svc.CustomerIsolation(context.Background(), providerOperator("op-1"), "tenant-x")
	if err != nil {
		t.Fatalf("siloed customer isolation: %v", err)
	}
	if siloed.Model != "siloed" || siloed.PostgresSchema != "tenant_x" || siloed.JetStreamSubjectLane != "x-lane" || siloed.ObjectKeyPrefix != "silo/x/" ||
		!siloed.AuditStream.Exists || siloed.AuditStream.Messages != 12 || siloed.AuditStream.Name != "TRSTCTL_AUDIT_x-lane" {
		t.Fatalf("siloed isolation = %+v, want the router's targets and the audit stream", siloed)
	}
	pooled, err := svc.CustomerIsolation(context.Background(), providerOperator("op-1"), "tenant-y")
	if err != nil || pooled.Model != "pooled" || pooled.PostgresSchema != "" || pooled.JetStreamSubjectLane != "" || pooled.AuditStream.Exists {
		t.Fatalf("pooled isolation = %+v %v, want the pooled model with no invented targets", pooled, err)
	}
	if _, err := svc.CustomerIsolation(context.Background(), providerOperator("stranger"), "tenant-x"); err == nil {
		t.Fatal("an operator without the customer's read delegation read its isolation")
	}

	req := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/tenant-x/isolation", nil)
	req.Header.Set("Authorization", "Bearer a96")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET isolation = %d %s", rec.Code, rec.Body.String())
	}
	var body CustomerIsolation
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.TenantID != "tenant-x" || body.Model != "siloed" || body.AuditStream.Messages != 12 {
		t.Fatalf("served isolation = %s %v", rec.Body.String(), err)
	}
	unauth := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants/tenant-x/isolation", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, unauth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated isolation read = %d, want 401", rec.Code)
	}
}
