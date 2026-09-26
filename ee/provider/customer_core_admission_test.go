// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// A license removal must not undo an already accepted restriction. Exercise
// the core admission callback with a real credential, without a Provider check.
func TestProviderRestrictionSurvivesCoreOnlyAdmissionAndRebuild(t *testing.T) {
	for _, status := range []TenantStatus{TenantSuspended, TenantOffboarded} {
		t.Run(string(status), func(t *testing.T) {
			st, log, sink := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
			ctx := t.Context()
			id := CustomerID("core-restriction-" + string(status))
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "core-restriction", Name: "Core restriction", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
			appendStatus := func(key, typ string, status TenantStatus) {
				t.Helper()
				tenant.Status = status
				if _, err := sink.Append(ctx, key, typ, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			appendStatus("provision", AuditTenantProvisioned, TenantActive)
			idem := orchestrator.NewIdempotency(st)
			projector := projections.New(st)
			payload := []byte(`{"name":"Core restriction"}`)
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
				orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "registration", RequestMaterial: payload,
					PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }}); err != nil {
				t.Fatal(err)
			}
			raw, hash, err := auth.GenerateAPIToken()
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(raw)
			if _, err := st.CreateAPIToken(ctx, corestore.APITokenRecord{TenantID: id, TokenHash: hash, Subject: "customer", Scopes: []string{"owners:read"}}); err != nil {
				t.Fatal(err)
			}
			customer := api.New(st, idem, orchestrator.NewOrchestrator(log, st, nil), api.WithTenantServiceCheck(st.RequireLiveTenantService))
			probe := func(want int) {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
				r.Header.Set("Authorization", "Bearer "+string(raw))
				w := httptest.NewRecorder()
				customer.ServeHTTP(w, r)
				if w.Code != want {
					t.Errorf("core-only customer read = %d, want %d", w.Code, want)
				}
			}
			probe(http.StatusOK)
			typ := AuditTenantSuspended
			if status == TenantOffboarded {
				typ = AuditTenantOffboarded
			}
			// This legacy offboard event retained customer data, unlike the new
			// erasure workflow. A downgrade must not turn that history into access.
			appendStatus("restrict", typ, status)
			probe(http.StatusForbidden)
			assertDenied := func() {
				t.Helper()
				if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
					t.Errorf("persisted %s core admission = %v, want unavailable", status, err)
				}
			}
			assertDenied()
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			assertDenied()
			probe(http.StatusForbidden)
			if err := NewAuthorityRuntime(st, log).Bootstrap(ctx); err != nil {
				t.Fatal(err)
			}
			assertDenied()
			if status == TenantSuspended {
				appendStatus("resume", AuditTenantResumed, TenantActive)
				probe(http.StatusOK)
			}
		})
	}
}
