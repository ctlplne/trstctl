// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestProviderRetainedSuspendDeniesCustomerBeforeProjection(t *testing.T) {
	st, log, _ := authorityReplayFixture(t)
	ctx := context.Background()
	id := uuid.NewString()
	now := time.Now().UTC()
	tenant := Tenant{ID: id, Slug: "suspend-gap", Name: "Suspend gap", Status: TenantActive,
		CreatedAt: now, UpdatedAt: now}
	runtime := NewAuthorityRuntime(st, log)
	if _, err := runtime.Mutations.Append(ctx, "provider-suspend-gap-provision", AuditTenantProvisioned, id,
		AuthorityEvent{Tenant: &tenant, EffectiveAt: now, Audit: AuditEvent{Type: AuditTenantProvisioned,
			TenantID: id, OperatorID: "op-1", At: now}}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(st, runtime.ProjectionOptions...)
	idem := orchestrator.NewIdempotency(st)
	registrationBody, _ := json.Marshal(map[string]string{"name": tenant.Name})
	if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
		orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name,
			IdempotencyKey: "provider-suspend-gap-register", RequestMaterial: registrationBody,
			PayloadAt: func(time.Time) ([]byte, error) { return registrationBody, nil }}); err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	handler := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st),
		Mutations: runtime.Mutations, Idempotency: idem,
		Authenticator: authorityAuthenticator{}, Delegations: fullyDelegated("op-1", id),
		Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)})
	runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
		if event.Type == AuditTenantSuspended {
			return errors.New("qa injected Provider suspension projection outage")
		}
		return nil
	}
	request := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/suspend", nil)
	request.Header.Set("Authorization", "Bearer requester")
	request.Header.Set("Idempotency-Key", "provider-suspend-gap")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusNoContent {
		t.Fatal("suspend reported success while its projection failed")
	}
	eventID := uuid.NewSHA1(providerMutationNamespace, []byte(id+"\x00provider-suspend-gap")).String()
	retained, found, err := log.EventByID(ctx, eventID)
	if err != nil || !found || retained.Type != AuditTenantSuspended {
		t.Fatalf("retained suspend = %+v found=%t err=%v", retained, found, err)
	}
	if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantActive {
		t.Fatalf("fault precondition: projected Provider status = %+v err=%v", current, err)
	}
	listed, err := NewPGStore(st).ListTenants(ctx)
	if err != nil || len(listed) != 1 || listed[0].Status != TenantSuspensionPending {
		t.Fatalf("operator list hid pending denial: %+v err=%v", listed, err)
	}
	if health, err := NewPGStore(st).DirectTenantSnapshot(ctx, id); err != nil || health.Health != "suspension_pending" {
		t.Fatalf("operator health hid pending denial: %+v err=%v", health, err)
	}
	if err := NewPGStore(st).RequireCustomerService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("retained suspension left customer admitted: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("core admission ignored retained suspension: %v", err)
	}
	offboard := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/offboard", nil)
	offboard.Header.Set("Authorization", "Bearer requester")
	offboard.Header.Set("Idempotency-Key", "provider-suspend-gap-offboard")
	refusedOffboard := httptest.NewRecorder()
	handler.ServeHTTP(refusedOffboard, offboard)
	if refusedOffboard.Code != http.StatusConflict {
		t.Fatalf("offboard overtook pending suspension: %d %s", refusedOffboard.Code, refusedOffboard.Body.String())
	}
	runtime.Projection.applyHook = nil
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, request.Clone(ctx))
	if retry.Code != http.StatusNoContent {
		t.Fatalf("same-key suspension recovery = %d: %s", retry.Code, retry.Body.String())
	}
	command, err := st.ProviderSuspendCommand(ctx, id, eventID)
	if err != nil || command.Status != "completed" || len(command.Event.Data) != 0 {
		t.Fatalf("completed command = %+v err=%v", command, err)
	}
	resume := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/resume", nil)
	resume.Header.Set("Authorization", "Bearer requester")
	resume.Header.Set("Idempotency-Key", "provider-suspend-gap-resume")
	resumed := httptest.NewRecorder()
	handler.ServeHTTP(resumed, resume)
	if resumed.Code != http.StatusNoContent {
		t.Fatalf("resume = %d: %s", resumed.Code, resumed.Body.String())
	}
	if err := st.RequireLiveTenantService(ctx, id); err != nil {
		t.Fatalf("projected resume did not release exact denial: %v", err)
	}
	if err := NewAuthorityRuntime(st, log).Bootstrap(ctx); err != nil {
		t.Fatalf("cold Provider authority bootstrap: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, id); err != nil {
		t.Fatalf("cold resume readback: %v", err)
	}
	// Crash after the SQL denial commit and before any broker publish. Startup
	// must publish the exact first command, project it, and keep service denied.
	preappendAt := time.Now().UTC().Truncate(time.Microsecond)
	tenant.Status, tenant.UpdatedAt = TenantSuspended, preappendAt
	preappendPayload, err := json.Marshal(AuthorityEvent{Tenant: &tenant,
		Audit: AuditEvent{Type: AuditTenantSuspended, TenantID: id, OperatorID: "op-1", At: preappendAt}})
	if err != nil {
		t.Fatal(err)
	}
	preappendID := uuid.NewString()
	preappend := events.Event{ID: preappendID, Type: AuditTenantSuspended,
		TenantID: id, Time: preappendAt, SchemaVersion: events.DefaultSchemaVersion,
		Data: preappendPayload}
	if _, err := st.ClaimProviderSuspendCommand(ctx, preappend); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventByID(ctx, preappendID); err != nil || found {
		t.Fatalf("preappend fault setup retained event=%t err=%v", found, err)
	}
	if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("preappend suspension left core admitted: %v", err)
	}
	if err := NewAuthorityRuntime(st, log).Bootstrap(ctx); err != nil {
		t.Fatalf("recover preappend suspension: %v", err)
	}
	if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantSuspended {
		t.Fatalf("recovered suspension = %+v err=%v", current, err)
	}
	if command, err := st.ProviderSuspendCommand(ctx, id, preappendID); err != nil || command.Status != "completed" {
		t.Fatalf("recovered command = %+v err=%v", command, err)
	}
	if err := NewAuthorityRuntime(st, log).Bootstrap(ctx); err != nil {
		t.Fatalf("second cold Provider authority bootstrap: %v", err)
	}
	if command, err := st.ProviderSuspendCommand(ctx, id, preappendID); err != nil || command.Status != "completed" {
		t.Fatalf("older resume released newer suspension during replay: %+v err=%v", command, err)
	}
	if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("repeated cold replay reopened suspended customer: %v", err)
	}
}
