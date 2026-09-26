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

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestProviderOffboardHTTPRecoversAfterEraseBeforeResult(t *testing.T) {
	for _, stage := range []string{"after-erase", "projection", "projection-later-authority", "projection-continuation", "projection-legacy-registration"} {
		t.Run(stage, func(t *testing.T) {
			st, log, sink := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
			ctx := t.Context()
			id := CustomerID("offboard-interrupted-http-result-" + stage)
			now := time.Now().UTC()
			tenant := Tenant{ID: id, Slug: "offboard-interrupted-http-result", Name: "Interrupted result", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
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
			payload := []byte(`{"name":"Interrupted result"}`)
			if stage == "projection-legacy-registration" {
				legacy, err := log.Append(ctx, events.Event{ID: "77777777-7777-4777-8777-777777777777",
					Type: projections.EventTenantRegistered, TenantID: id, Data: payload})
				if err != nil {
					t.Fatal(err)
				}
				if err := projector.ApplyRetainedTenantLifecycle(ctx, legacy); err != nil {
					t.Fatal(err)
				}
			} else if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
				orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "registration", RequestMaterial: payload,
					PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }}); err != nil {
				t.Fatal(err)
			}
			orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
			offboarding := NewTenantOffboarder(st, log, orch, runtime.Mutations)
			if stage == "after-erase" {
				offboarding.afterErase = func() error { return errors.New("test: connection lost before HTTP result") }
			} else {
				runtime.Projection.applyHook = func(_ context.Context, event events.Event) error {
					if event.Type == projections.EventTenantOffboarded {
						return errors.New("test: lifecycle projection interrupted")
					}
					return nil
				}
			}
			config := Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
				Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: NewPGDelegationSource(st), Offboarding: offboarding,
				Activity: NewEventLogActivitySource(log)}
			handler := NewHandler(config)
			request := func(key, bearer, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/offboard", strings.NewReader(body))
				r.Header.Set("Authorization", bearer)
				r.Header.Set("Idempotency-Key", key)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			first := request("erase", "Bearer requester", `{}`)
			if first.Code != http.StatusInternalServerError {
				t.Fatalf("interrupted response=%d %s", first.Code, first.Body.String())
			}
			if strings.HasPrefix(stage, "projection") {
				if got, err := NewPGStore(st).Tenant(ctx, id); err != nil || got.Status != TenantOffboarding {
					t.Fatalf("failed erase must remain visibly pending: %+v %v", got, err)
				}
				if _, err := st.GetTenant(ctx, id); err != nil {
					t.Fatalf("failed transaction lost tenant: %v", err)
				}
				runtime.Projection.applyHook = nil
				if stage == "projection-later-authority" {
					// Another customer's inline command can commit after the erase
					// event was appended but its lifecycle transaction rolled back.
					other := Tenant{ID: CustomerID("later-authority"), Slug: "later-authority", Name: "Other customer",
						Status: TenantActive, CreatedAt: now, UpdatedAt: now}
					if _, err := sink.Append(ctx, "later-provision", AuditTenantProvisioned, other.ID,
						AuthorityEvent{Tenant: &other, EffectiveAt: now}); err != nil {
						t.Fatal(err)
					}
				} else if err := runtime.Bootstrap(ctx); err != nil {
					t.Fatal(err)
				}
				if err := NewPGStore(st).RequireCustomerService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
					t.Fatalf("authority recovery reopened customer before core erase completed: %v", err)
				}
			} else if _, err := NewPGStore(st).Tenant(ctx, id); !errors.Is(err, ErrNotFound) {
				t.Fatalf("interruption occurred before deletion: %v", err)
			}
			set, err := NewPGDelegationSource(st).Delegations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Authorize(providerOperator("op-1"), id, OpOffboard); err == nil && stage != "projection-later-authority" {
				t.Fatal("completed erase kept original authority")
			}
			head, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Reassemble the command and handler, retaining only database/event state.
			config.Offboarding = NewTenantOffboarder(st, log, orch, runtime.Mutations)
			handler = NewHandler(config)
			if stage == "projection-continuation" {
				activityRequest := httptest.NewRequest(http.MethodGet, "/provider/v1/activity", nil)
				activityRequest.Header.Set("Authorization", "Bearer requester")
				activityResult := httptest.NewRecorder()
				handler.ServeHTTP(activityResult, activityRequest)
				var activity struct {
					Items []struct {
						RequestID   string `json:"request_event_id"`
						State       string `json:"offboard_state"`
						CanContinue bool   `json:"can_continue_offboard"`
					} `json:"items"`
				}
				if activityResult.Code != http.StatusOK || json.Unmarshal(activityResult.Body.Bytes(), &activity) != nil ||
					len(activity.Items) != 1 || activity.Items[0].State != "pending" || !activity.Items[0].CanContinue {
					t.Fatalf("operator lost pending request after customer disappeared: %d %s", activityResult.Code, activityResult.Body.String())
				}
				var requestID string
				if err := log.Replay(ctx, 0, func(event events.Event) error {
					if event.Type == AuditTenantErasureRequested && event.TenantID == id {
						requestID = event.ID
					}
					return nil
				}); err != nil || requestID == "" {
					t.Fatalf("retained operation reference: %q %v", requestID, err)
				}
				if activity.Items[0].RequestID != requestID {
					t.Fatal("activity did not expose the exact retained request")
				}
				body, err := json.Marshal(map[string]string{"request_event_id": requestID})
				if err != nil {
					t.Fatal(err)
				}
				if got := request("resume-unauthenticated", "", string(body)); got.Code != http.StatusUnauthorized {
					t.Fatalf("unauthenticated continuation=%d", got.Code)
				}
				for _, actor := range []Operator{
					{ID: "op-1", Role: OperatorAdmin, MFA: false},
					{ID: "op-1", Role: OperatorOperator, MFA: true},
				} {
					limited := config
					limited.Authenticator = consoleAuthorityAuth{actor}
					handler = NewHandler(limited)
					if got := request("resume-limited-"+string(actor.Role), "Bearer requester", string(body)); got.Code != http.StatusForbidden {
						t.Fatalf("continuation bypassed current MFA/role: %d", got.Code)
					}
				}
				readOnly := config
				readOnly.License = readOnlyConsentLicense(t)
				handler = NewHandler(readOnly)
				if got := request("resume-readonly", "Bearer requester", string(body)); got.Code != http.StatusForbidden {
					t.Fatalf("continuation bypassed current entitlement: %d", got.Code)
				}
				handler = NewHandler(config)
				if got := request("resume-after-restart", "Bearer requester", string(body)); got.Code != http.StatusNoContent {
					t.Fatalf("original operator could not resume by durable reference: %d %s", got.Code, got.Body.String())
				}
				if got := request("resume-other-operator", "Bearer approver-a", string(body)); got.Code != http.StatusConflict {
					t.Fatalf("another operator resumed original authorization: %d %s", got.Code, got.Body.String())
				}
				if after, err := log.LastSequence(ctx); err != nil || after != head+1 {
					t.Fatalf("continuation minted another command: %d %d %v", head, after, err)
				}
				activityResult = httptest.NewRecorder()
				handler.ServeHTTP(activityResult, activityRequest)
				activity.Items = nil // Decode each response independently; omitted false fields must not inherit old values.
				if activityResult.Code != http.StatusOK || json.Unmarshal(activityResult.Body.Bytes(), &activity) != nil || len(activity.Items) != 2 {
					t.Fatalf("completion activity=%d %s", activityResult.Code, activityResult.Body.String())
				}
				for _, item := range activity.Items {
					if item.RequestID != requestID || item.State != "completed" || item.CanContinue {
						t.Fatalf("completion not reflected by exact request: %+v", item)
					}
				}
				activityRequest.Header.Set("Authorization", "Bearer approver-a")
				activityResult = httptest.NewRecorder()
				handler.ServeHTTP(activityResult, activityRequest)
				activity.Items = nil
				if activityResult.Code != http.StatusOK || json.Unmarshal(activityResult.Body.Bytes(), &activity) != nil || len(activity.Items) != 0 {
					t.Fatalf("own-result exception leaked another operator's activity: %d %s", activityResult.Code, activityResult.Body.String())
				}
			}
			for _, changed := range []struct{ bearer, body string }{
				{"Bearer approver-a", `{}`}, {"Bearer requester", `{"changed":true}`},
			} {
				if got := request("erase", changed.bearer, changed.body); got.Code != http.StatusConflict {
					t.Fatalf("changed pending request=%d %s", got.Code, got.Body.String())
				}
			}
			second := request("erase", "Bearer requester", `{}`)
			if second.Code != http.StatusNoContent || second.Header().Get("Idempotent-Replayed") != "" {
				t.Fatalf("recover deleted customer's result=%d %s", second.Code, second.Body.String())
			}
			completions := 0
			if err := log.Replay(ctx, head+1, func(event events.Event) error {
				if event.Type != "provider.tenant_erasure.completed" || event.TenantID != id {
					t.Fatalf("retry appended an unexpected effect: %s %s", event.Type, event.TenantID)
				}
				completions++
				return nil
			}); err != nil || completions != 1 {
				t.Fatalf("verified deletion completion: count=%d err=%v", completions, err)
			}
			third := request("erase", "Bearer requester", `{}`)
			if third.Code != http.StatusNoContent || third.Header().Get("Idempotent-Replayed") != "true" {
				t.Fatalf("replay recovered result=%d %s", third.Code, third.Body.String())
			}
			if after, err := log.LastSequence(ctx); err != nil || after != head+1 {
				t.Fatalf("recovery appended another effect: before=%d after=%d error=%v", head, after, err)
			}
			if stage == "projection-later-authority" {
				if other, err := NewPGStore(st).Tenant(ctx, CustomerID("later-authority")); err != nil || other.Status != TenantActive {
					t.Fatalf("ordered recovery damaged another customer: %+v %v", other, err)
				}
			}
			if got := request("another-erase", "Bearer requester", `{}`); got.Code != http.StatusForbidden {
				t.Fatalf("new request borrowed old authority=%d %s", got.Code, got.Body.String())
			}
		})
	}
}

// The transport receipt must survive the customer erase it reports. Core
// deletion is invoked explicitly here to isolate receipt lifetime from the
// still-separate Provider command wiring; this is not an installed journey.
func TestProviderOffboardHTTPReceiptSurvivesCustomerErasure(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "op-1", Roles: []string{"admin"}})
	runtime := NewAuthorityRuntime(st, log)
	projector := projections.New(st, runtime.ProjectionOptions...)
	idem := orchestrator.NewIdempotency(st)
	orch := orchestrator.NewOrchestrator(log, st, nil, orchestrator.WithProjector(projector))
	newHandler := func() http.Handler {
		return NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st),
			Mutations: runtime.Mutations, Idempotency: idem, Authenticator: authorityAuthenticator{},
			Delegations: NewPGDelegationSource(st)})
	}
	handler := newHandler()
	request := func(customer, key, bearer, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+customer+"/offboard", strings.NewReader(body))
		r.Header.Set("Authorization", bearer)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, slug := range []string{"offboard-http-receipt-first", "offboard-http-receipt-other"} {
		id := CustomerID(slug)
		now := time.Now().UTC()
		tenant := Tenant{ID: id, Slug: slug, Name: "Receipt customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
		if _, err := sink.Append(ctx, "provision-"+id, AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := sink.Append(ctx, "grant-"+id, EventDelegationGranted, id, AuthorityEvent{
			Delegation: &DelegationMutation{OperatorID: "op-1", CustomerID: id, Operation: OpOffboard, GrantedBy: "admin"}, EffectiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		payload := []byte(`{"name":"Receipt customer"}`)
		registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
			orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "registration",
				RequestMaterial: payload, PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
		if err != nil {
			t.Fatal(err)
		}
		first := request(id, "same-key-per-customer", "Bearer requester", `{}`)
		if first.Code != http.StatusNoContent || first.Header().Get("Idempotent-Replayed") != "" {
			t.Fatalf("first offboard %s = %d %s", id, first.Code, first.Body.String())
		}
		if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: id, RegistrationIdentity: registration.ID}); err != nil {
			t.Fatal(err)
		}
		handler = newHandler()
		retry := request(id, "same-key-per-customer", "Bearer requester", `{}`)
		if retry.Code != http.StatusNoContent || retry.Header().Get("Idempotent-Replayed") != "true" || retry.Body.String() != first.Body.String() {
			t.Fatalf("retry after erasure = %d replay=%q body=%s", retry.Code, retry.Header().Get("Idempotent-Replayed"), retry.Body.String())
		}
		for _, changed := range []struct{ bearer, body string }{
			{"Bearer requester", `{"changed":true}`},
			{"Bearer approver-a", `{}`},
		} {
			got := request(id, "same-key-per-customer", changed.bearer, changed.body)
			if got.Code != http.StatusConflict {
				t.Fatalf("changed caller/body borrowed result: %d %s", got.Code, got.Body.String())
			}
		}
		if got := request(id, "new-command", "Bearer requester", `{}`); got.Code != http.StatusForbidden {
			t.Fatalf("new key borrowed revoked authority: %d %s", got.Code, got.Body.String())
		}
	}
}
