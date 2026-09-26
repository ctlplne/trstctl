// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestProviderOffboardRequestFailureRetainsCoreAdmissionDenial(t *testing.T) {
	for _, stage := range []string{"request-projection", "before-request-append"} {
		t.Run(stage, func(t *testing.T) {
			st, log, sink := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
			ctx := t.Context()
			id := CustomerID("request-projection-core-admission-" + stage)
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "request-projection-core-admission", Name: "Core admission", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
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
			idem := orchestrator.NewIdempotency(st)
			payload := []byte(`{"name":"Core admission"}`)
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
				orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "registration", RequestMaterial: payload,
					PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }}); err != nil {
				t.Fatal(err)
			}
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			if err := st.RequireLiveTenantService(ctx, id); err != nil {
				t.Fatal(err)
			}
			runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
				if event.Type == AuditTenantErasureRequested && stage == "request-projection" {
					return errors.New("test: request projection interrupted")
				}
				return nil
			}
			cfg := Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations, Idempotency: idem,
				Authenticator: authorityAuthenticator{}, Delegations: NewPGDelegationSource(st), Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)}
			if stage == "before-request-append" {
				cfg.Offboarding.beforeRequestAppend = func() error { return errors.New("test: before Provider append") }
			}
			request := func(handler http.Handler) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/offboard", strings.NewReader(`{}`))
				r.Header.Set("Authorization", "Bearer requester")
				r.Header.Set("Idempotency-Key", "erase")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			if result := request(NewHandler(cfg)); result.Code != http.StatusInternalServerError {
				t.Fatalf("interruption = %d %s", result.Code, result.Body.String())
			}
			if _, err := st.GetTenant(ctx, id); err != nil {
				t.Fatalf("pre-erasure interruption lost tenant: %v", err)
			}
			assertCoreDenied := func() {
				t.Helper()
				// This is the core check Build always installs, without the licensed
				// Provider callback. Losing the attachment must not restore access.
				if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
					t.Errorf("core-only admission after retained erase request = %v, want unavailable", err)
				}
			}
			assertCoreDenied()
			if err := projections.New(st).Rebuild(ctx, log); err != nil {
				t.Fatalf("core-only rebuild: %v", err)
			}
			assertCoreDenied()
			cfg.Offboarding.beforeRequestAppend = nil
			runtime.Projection.applyHook = nil
			if err := runtime.Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			assertCoreDenied()
			if result := request(NewHandler(cfg)); result.Code != http.StatusNoContent {
				t.Fatalf("authorized exact retry = %d %s", result.Code, result.Body.String())
			}
			if _, err := st.GetTenant(ctx, id); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("retry did not erase tenant: %v", err)
			}
		})
	}
}
