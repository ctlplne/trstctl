// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestProviderOffboardUnregisteredCustomer(t *testing.T) {
	for _, stage := range []string{"normal", "projection", "after-erase", "core-data", "enrollment-race"} {
		t.Run(stage, func(t *testing.T) { testProviderOffboardUnregisteredCustomer(t, stage) })
	}
}

func testProviderOffboardUnregisteredCustomer(t *testing.T, stage string) {
	st, log, sink := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
	ctx := t.Context()
	id := CustomerID("unregistered-offboard-" + stage)
	now := time.Now().UTC()
	tenant := Tenant{ID: id, Slug: "unregistered-offboard-" + stage, Name: "Unenrolled customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
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
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	offboarding := NewTenantOffboarder(st, log, orch, runtime.Mutations)
	var lateRegistration events.Event
	switch stage {
	case "projection":
		runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
			if event.Type == AuditUnregisteredTenantOffboarded {
				return errors.New("test: metadata completion SQL interrupted")
			}
			return nil
		}
	case "after-erase":
		offboarding.afterErase = func() error { return errors.New("test: metadata receipt interrupted") }
	case "core-data":
		if _, err := orch.CreateOwner(ctx, id, "team", "Existing workload record", "qa@example.test"); err != nil {
			t.Fatal(err)
		}
	case "enrollment-race":
		runtime.Projection.applyHook = func(ctx context.Context, event events.Event) error {
			if event.Type != AuditTenantErasureRequested {
				return nil
			}
			data := []byte(`{"name":"Concurrent enrollment"}`)
			var err error
			lateRegistration, err = orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, orchestrator.NewIdempotency(st),
				orchestrator.TenantRegistrationCommand{TenantID: id, Name: "Concurrent enrollment", IdempotencyKey: "concurrent-registration",
					RequestMaterial: data, PayloadAt: func(time.Time) ([]byte, error) { return data, nil }})
			return err
		}
	}
	config := Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
		Idempotency: orchestrator.NewIdempotency(st), Authenticator: authorityAuthenticator{}, Delegations: NewPGDelegationSource(st),
		Offboarding: offboarding}
	handler := NewHandler(config)
	requestKey := "erase-unregistered"
	requestBody := `{}`
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/offboard", strings.NewReader(requestBody))
		r.Header.Set("Authorization", "Bearer requester")
		r.Header.Set("Idempotency-Key", requestKey)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if stage == "core-data" || stage == "enrollment-race" {
		if w := request(); w.Code != http.StatusConflict {
			t.Fatalf("metadata-only erase accepted workload data: %d %s", w.Code, w.Body.String())
		}
		if stage == "enrollment-race" {
			if got, err := st.GetTenant(ctx, id); err != nil || got.EventSeq != lateRegistration.Sequence {
				t.Fatalf("metadata-only erase changed new registration: %+v %v", got, err)
			}
		} else if got, err := st.ListOwners(ctx, id); err != nil || len(got) != 1 {
			t.Fatalf("metadata-only erase changed workload data: %+v %v", got, err)
		}
		if err := log.Replay(ctx, 0, func(event events.Event) error {
			if event.TenantID == id && (event.Type == AuditUnregisteredTenantOffboarded || event.Type == projections.EventTenantOffboarded) {
				t.Fatal("refused metadata erase appended a completion")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if stage == "enrollment-race" {
			runtime.Projection.applyHook = nil
			if err := runtime.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			current, err := NewPGStore(st).Tenant(ctx, id)
			if err != nil || current.Status != TenantOffboardFailed {
				t.Fatalf("refused erase left an unrecoverable pending status: %+v %v", current, err)
			}
			if err := NewPGStore(st).RequireCustomerService(ctx, id); err == nil {
				t.Fatal("failed deletion reopened customer service")
			}
			if count, err := NewPGStore(st).CountBillableTenants(ctx); err != nil || count != 1 {
				t.Fatalf("failed deletion lost billable customer: count=%d err=%v", count, err)
			}
			if snapshot, err := NewPGStore(st).DirectTenantSnapshot(ctx, id); err != nil || snapshot.Health != "offboard_failed" {
				t.Fatalf("failed deletion health disagrees with recovered state: %+v %v", snapshot, err)
			}
			requestKey = "erase-current-registration"
			if w := request(); w.Code != http.StatusNoContent {
				t.Fatalf("new authorized request could not recover: %d %s", w.Code, w.Body.String())
			}
			if _, err := st.GetTenant(ctx, id); !corestore.IsNotFound(err) {
				t.Fatalf("recovered deletion retained core customer: %v", err)
			}
		}
		return
	}
	if stage != "normal" {
		if w := request(); w.Code != http.StatusInternalServerError {
			t.Fatalf("interruption response=%d %s", w.Code, w.Body.String())
		}
		switch stage {
		case "projection":
			if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantOffboarding {
				t.Fatalf("interrupted SQL was not rolled back: %+v %v", current, err)
			}
		}
		runtime.Projection.applyHook = nil
		if err := runtime.Bootstrap(ctx); err != nil {
			t.Fatal(err)
		}
		config.Offboarding = NewTenantOffboarder(st, log, orch, runtime.Mutations)
		handler = NewHandler(config)
	}
	if w := request(); w.Code != http.StatusNoContent {
		t.Fatalf("offboard before enrollment=%d %s", w.Code, w.Body.String())
	}
	if got, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("offboard retained registry: %+v %v", got, err)
	}
	if set, err := NewPGDelegationSource(st).Delegations(ctx); err != nil || set.Authorize(providerOperator("op-1"), id, OpOffboard) == nil {
		t.Fatalf("offboard retained authority: %v", err)
	}
	if w := request(); w.Code != http.StatusNoContent || w.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("offboard receipt=%d replay=%q", w.Code, w.Header().Get("Idempotent-Replayed"))
	}
	if err := runtime.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery resurrected unenrolled customer: %v", err)
	}
	if err := projections.New(st, runtime.ProjectionOptions...).Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("full rebuild resurrected unenrolled customer: %v", err)
	}
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == id && (event.Type == projections.EventTenantRegistered || event.Type == projections.EventTenantOffboarded) {
			t.Fatalf("metadata-only customer invented a core lifecycle: %s", event.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Later explicit provisioning and core registration are a new lifecycle.
	// An old request may recover its result but must never repeat deletion.
	later := tenant
	later.CreatedAt, later.UpdatedAt = now.Add(time.Hour), now.Add(time.Hour)
	if _, err := sink.Append(ctx, "new-provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &later, EffectiveAt: later.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"name":"New registered customer"}`)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, orchestrator.NewIdempotency(st),
		orchestrator.TenantRegistrationCommand{TenantID: id, Name: "New registered customer", IdempotencyKey: "new-registration",
			RequestMaterial: data, PayloadAt: func(time.Time) ([]byte, error) { return data, nil }})
	if err != nil {
		t.Fatal(err)
	}
	// Explicitly expire this one test HTTP cache row. A rebuild may preserve
	// operational receivers; do not assume it forced source-command recovery.
	if err := st.WithTenant(ctx, corestore.ZeroUUID, func(tx pgx.Tx) error {
		key := "provider.offboard.result.v1/" + crypto.SHA256Hex([]byte(id+"\x00erase-unregistered"))
		_, err := tx.Exec(ctx, `DELETE FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, corestore.ZeroUUID, key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w := request(); w.Code != http.StatusNoContent || w.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("old receipt after new lifecycle=%d %s", w.Code, w.Body.String())
	}
	if err := runtime.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := NewPGStore(st).Tenant(ctx, id); err != nil || got.Status != TenantActive || !got.CreatedAt.Equal(later.CreatedAt.Truncate(time.Microsecond)) {
		t.Fatalf("old request changed new Provider customer: %+v %v", got, err)
	}
	if got, err := st.GetTenant(ctx, id); err != nil || got.EventSeq != registration.Sequence {
		t.Fatalf("old request changed new core registration: %+v %v", got, err)
	}
	var oldRequestID string
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == AuditTenantErasureRequested && event.TenantID == id {
			oldRequestID = event.ID
		}
		return nil
	}); err != nil || oldRequestID == "" {
		t.Fatalf("old request reference: %q %v", oldRequestID, err)
	}
	body, err := json.Marshal(map[string]string{"request_event_id": oldRequestID})
	if err != nil {
		t.Fatal(err)
	}
	requestKey, requestBody = "continue-old-lifecycle", string(body)
	if w := request(); w.Code != http.StatusNoContent {
		t.Fatalf("old lifecycle continuation=%d %s", w.Code, w.Body.String())
	}
	if err := runtime.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetTenant(ctx, id); err != nil || got.EventSeq != registration.Sequence {
		t.Fatalf("continuation erased newer core registration: %+v %v", got, err)
	}
	if got, err := NewPGStore(st).Tenant(ctx, id); err != nil || got.Status != TenantActive || !got.CreatedAt.Equal(later.CreatedAt.Truncate(time.Microsecond)) {
		t.Fatalf("completion witness changed newer Provider state: %+v %v", got, err)
	}
}
