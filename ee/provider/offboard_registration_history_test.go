// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestProviderOffboardHTTPRequiresRetainedRegistration(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "source-absent"
		if retained {
			name = "read-model-anchor-lost"
		}
		t.Run(name, func(t *testing.T) {
			st, log, sink := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
			ctx := t.Context()
			id := CustomerID("unanchored-" + name)
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "unanchored-" + name, Name: "Historical customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
			if _, err := sink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := sink.Append(ctx, "grant", EventDelegationGranted, id, AuthorityEvent{
				Delegation: &DelegationMutation{OperatorID: "op-1", CustomerID: id, Operation: OpOffboard, GrantedBy: "admin"}, EffectiveAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			runtime := NewAuthorityRuntime(st, log)
			projector := projections.New(st, runtime.ProjectionOptions...)
			if retained {
				registration, err := log.Append(ctx, events.Event{ID: "old-registration-before-durable-ids", Type: projections.EventTenantRegistered,
					TenantID: id, Data: []byte(`{"name":"Historical customer"}`)})
				if err != nil {
					t.Fatal(err)
				}
				if err := projector.ApplyRetainedTenantLifecycle(ctx, registration); err != nil {
					t.Fatal(err)
				}
			}
			// Fault injection: either an out-of-band row with no source, or a
			// damaged projection that lost its retained registration position.
			if err := st.UpsertTenant(ctx, corestore.Tenant{TenantID: id, Name: tenant.Name}); err != nil {
				t.Fatal(err)
			}
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			if _, err := orch.CreateOwner(ctx, id, "team", "Retain this data", "qa@example.test"); err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
				Idempotency: orchestrator.NewIdempotency(st), Authenticator: authorityAuthenticator{}, Delegations: NewPGDelegationSource(st),
				Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)})
			request := func(key string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/offboard", strings.NewReader(`{}`))
				r.Header.Set("Authorization", "Bearer requester")
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			head, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := request("unanchored-delete"); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "retained registration") {
				t.Fatalf("unanchored deletion did not explain recovery requirement: %d %s", got.Code, got.Body.String())
			}
			if after, err := log.LastSequence(ctx); err != nil || after != head {
				t.Fatalf("refusal fabricated source history: %d %d %v", head, after, err)
			}
			if current, err := st.GetTenant(ctx, id); err != nil || current.EventSeq != 0 {
				t.Fatalf("refusal changed unanchored row: %+v %v", current, err)
			}
			if owners, err := st.ListOwners(ctx, id); err != nil || len(owners) != 1 {
				t.Fatalf("refusal lost workload data: %+v %v", owners, err)
			}
			if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantActive {
				t.Fatalf("refusal changed Provider state: %+v %v", current, err)
			}
			if !retained {
				return // Missing source needs real history recovery, never an invented registration.
			}
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			if got := request("after-history-recovery"); got.Code != http.StatusNoContent {
				t.Fatalf("recovered retained registration could not offboard: %d %s", got.Code, got.Body.String())
			}
			if _, err := st.GetTenant(ctx, id); !corestore.IsNotFound(err) {
				t.Fatalf("verified recovery retained tenant: %v", err)
			}
			if _, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
				t.Fatalf("verified recovery retained registry: %v", err)
			}
		})
	}
}
