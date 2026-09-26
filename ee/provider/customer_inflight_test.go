// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

type holdCustomerRequest struct{}

func TestProviderStatusRefusesWhileCustomerWorkIsInFlight(t *testing.T) {
	for _, tc := range []struct{ lane, action string }{{"request", "suspend"}, {"delivery", "suspend"}, {"request", "offboard"}, {"delivery", "offboard"}} {
		lane, action := tc.lane, tc.action
		t.Run(action+"/"+lane, func(t *testing.T) {
			st, log, runtimeSink := authorityReplayFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			id := CustomerID("in-flight-" + action + "-" + lane)
			runtime := NewAuthorityRuntime(st, log)
			projector := projections.New(st, runtime.ProjectionOptions...)
			idem := orchestrator.NewIdempotency(st)
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "in-flight-" + action + "-" + lane, Name: "In-flight customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
			if _, err := runtimeSink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"name":"In-flight customer"}`)
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem, orchestrator.TenantRegistrationCommand{
				TenantID: id, Name: tenant.Name, IdempotencyKey: "register-" + lane, RequestMaterial: payload,
				PayloadAt: func(time.Time) ([]byte, error) { return payload, nil },
			}); err != nil {
				t.Fatal(err)
			}
			provider := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
				Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: &mutableDelegations{set: fullyDelegated("op-1", id)},
				Offboarding: NewTenantOffboarder(st, log, orch, runtime.Mutations)})
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			hold := func(ctx context.Context) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			finished := make(chan error, 1)
			if lane == "request" {
				raw, hash, err := auth.GenerateAPIToken()
				if err != nil {
					t.Fatal(err)
				}
				defer secret.Wipe(raw)
				if _, err := st.CreateAPIToken(ctx, corestore.APITokenRecord{TenantID: id, TokenHash: hash, Subject: "customer", Scopes: []string{"owners:write"}}); err != nil {
					t.Fatal(err)
				}
				customer := api.New(st, idem, orch, api.WithTenantServiceCheck(func(ctx context.Context, tenantID string) error {
					if err := NewPGStore(st).RequireCustomerService(ctx, tenantID); err != nil {
						return err
					}
					if ctx.Value(holdCustomerRequest{}) == true {
						return hold(ctx)
					}
					return nil
				}))
				r := httptest.NewRequest(http.MethodPost, "/api/v1/owners", strings.NewReader(`{"kind":"team","name":"Admitted owner","email":"qa@example.test"}`))
				r = r.WithContext(context.WithValue(ctx, holdCustomerRequest{}, true))
				r.Header.Set("Authorization", "Bearer "+string(raw))
				r.Header.Set("Idempotency-Key", "admitted")
				go func() {
					w := httptest.NewRecorder()
					customer.ServeHTTP(w, r)
					if w.Code != http.StatusCreated {
						finished <- &unexpectedCustomerStatus{w.Code}
						return
					}
					finished <- nil
				}()
			} else {
				outbox := orchestrator.NewOutbox(st, orchestrator.WithTenantServiceCheck(NewPGStore(st).RequireCustomerService))
				if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
					_, err := outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: id, Destination: "inflight.probe", IdempotencyKey: "inflight-delivery", Payload: []byte(`{}`)})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				go func() {
					_, err := outbox.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(ctx context.Context, _ orchestrator.Message) error { return hold(ctx) }), orchestrator.DestinationScope{IncludePrefixes: []string{"inflight.probe"}})
					finished <- err
				}()
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			mutate := func(actor, key string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/"+action, strings.NewReader(`{}`)).WithContext(ctx)
				r.Header.Set("Authorization", "Bearer "+actor)
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				provider.ServeHTTP(w, r)
				return w
			}
			blocked := mutate("requester", "transition-inflight")
			unauthorized := mutate("approver-a", "ungranted-transition")
			// Always join the active operation before a failure can close its fixture.
			unblock()
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			if unauthorized.Code != http.StatusForbidden {
				t.Fatalf("ungranted caller learned workload state: %d %s", unauthorized.Code, unauthorized.Body.String())
			}
			if blocked.Code != http.StatusServiceUnavailable || blocked.Header().Get("Retry-After") != "1" {
				t.Fatalf("suspension completed while admitted %s was running: %d %s", lane, blocked.Code, blocked.Body.String())
			}
			if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantActive {
				t.Fatalf("busy suspension changed customer state: %+v %v", current, err)
			}
			if done := mutate("requester", "transition-inflight"); done.Code != http.StatusNoContent {
				t.Fatalf("same request could not suspend after work finished: %d %s", done.Code, done.Body.String())
			}
		})
	}
}

type unexpectedCustomerStatus struct{ status int }

func (e *unexpectedCustomerStatus) Error() string { return http.StatusText(e.status) }
