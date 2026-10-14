// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
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

func TestProviderSuspensionCannotOutliveItsServiceSession(t *testing.T) {
	st, log, sink := authorityReplayFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	id := CustomerID("lifecycle-session-loss")
	runtime := NewAuthorityRuntime(st, log)
	projector := projections.New(st, runtime.ProjectionOptions...)
	idem := orchestrator.NewIdempotency(st)
	now := time.Now().UTC()
	tenant := Tenant{ID: id, Slug: "lifecycle-session-loss", Name: "Lifecycle session loss", Status: TenantActive, CreatedAt: now, UpdatedAt: now}
	if _, err := sink.Append(ctx, "provision", AuditTenantProvisioned, id, AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"name":"Lifecycle session loss"}`)
	if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem, orchestrator.TenantRegistrationCommand{TenantID: id, Name: tenant.Name, IdempotencyKey: "register", RequestMaterial: payload, PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }}); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations, Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: &mutableDelegations{set: fullyDelegated("op-1", id)}})
	outbox := orchestrator.NewOutbox(st, orchestrator.WithTenantServiceCheck(st.RequireLiveTenantService))
	if err := st.WithTenant(ctx, id, func(tx pgx.Tx) error {
		_, err := outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: id, Destination: "lifecycle-session.probe", IdempotencyKey: "remote", Payload: []byte(`{}`)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	dispatched, workAdmitted := false, false
	var retained events.Event
	runtime.Projection.applyHook = func(hookCtx context.Context, event events.Event) error {
		if event.Type != AuditTenantSuspended || retained.ID != "" {
			return nil
		}
		retained = event
		var pid int32
		if err := st.SystemPool().QueryRow(hookCtx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND mode='ExclusiveLock' AND granted AND ((classid::bigint<<32)|objid::bigint)=hashtextextended($1,0)`, "tenant-service\x1f"+id).Scan(&pid); err != nil {
			return err
		}
		var killed bool
		if err := st.SystemPool().QueryRow(hookCtx, `SELECT pg_terminate_backend($1,5000)`, pid).Scan(&killed); err != nil || !killed {
			return fmt.Errorf("terminate owned lifecycle session: killed=%v error=%v", killed, err)
		}
		dispatched = true
		claimed, err := outbox.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
			workAdmitted = true
			return nil
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"lifecycle-session.probe"}})
		if !claimed || workAdmitted || !errors.Is(err, tenancy.ErrServiceUnavailable) {
			return fmt.Errorf("pre-append denial after lost session: claimed=%t admitted=%t error=%v", claimed, workAdmitted, err)
		}
		return nil
	}
	mutate := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants/"+id+"/suspend", strings.NewReader(`{}`)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer requester")
		r.Header.Set("Idempotency-Key", "suspend-session-loss")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := mutate()
	if retained.ID == "" || !dispatched {
		t.Fatalf("fault boundary was not reached: status=%d body=%s", w.Code, w.Body.String())
	}
	if workAdmitted {
		t.Fatal("lost service session admitted remote work after suspension claim")
	}
	if w.Code != http.StatusNoContent && w.Code != http.StatusInternalServerError {
		t.Fatalf("suspension after lost session = %d %s", w.Code, w.Body.String())
	}
	if err := st.RequireLiveTenantService(ctx, id); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("lost lifecycle session reopened customer service: %v", err)
	}
	// The earlier test expected a work handoff in this gap. The independent
	// denial now prevents it, so replay can safely converge the retained event.
	if err := runtime.Projection.Apply(ctx, retained); err != nil {
		t.Fatalf("retained suspension did not converge: %v", err)
	}
	if retry := mutate(); retry.Code != http.StatusNoContent {
		t.Fatalf("exact suspension did not recover after work completed: %d %s", retry.Code, retry.Body.String())
	}
	if current, err := NewPGStore(st).Tenant(ctx, id); err != nil || current.Status != TenantSuspended {
		t.Fatalf("recovered suspension missing: %+v %v", current, err)
	}
}
