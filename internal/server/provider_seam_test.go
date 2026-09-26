// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestProviderFactoryUsesAssembledLifecycleProjector(t *testing.T) {
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "factory-test", Roles: []string{"admin"}})
	st := newServerTestStore(t)
	log := openServerFederationSeamTestLog(t)
	const tenantID = "9ec4ec52-c8b1-4758-812e-4f943dc41d42"
	payload := []byte(`{"name":"Factory customer"}`)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projections.New(st), orchestrator.NewIdempotency(st),
		orchestrator.TenantRegistrationCommand{TenantID: tenantID, Name: "Factory customer", IdempotencyKey: "factory-registration", RequestMaterial: payload,
			PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	extension := &providerFactoryLifecycleProjection{}
	called := false
	srv, err := Build(ctx, Deps{Store: st, Log: log,
		LicensedProjectionOptions: []projections.Option{projections.WithEventProjection(extension)},
		ProviderHandlerFactory: func(orch *orchestrator.Orchestrator) (http.Handler, error) {
			called = true
			if orch == nil {
				return nil, errors.New("test: missing assembled orchestrator")
			}
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: tenantID, RegistrationIdentity: registration.ID}); err != nil {
					t.Errorf("factory command: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/provider/v1/probe", nil))
	if !called || w.Code != http.StatusNoContent || extension.offboards != 1 {
		t.Fatalf("factory=%v response=%d lifecycle projections=%d", called, w.Code, extension.offboards)
	}
}

func TestProviderFactoryFailurePreventsServing(t *testing.T) {
	for _, kind := range []string{"error", "nil handler"} {
		t.Run(kind, func(t *testing.T) {
			failure := errors.New("test: Provider assembly unavailable")
			srv, err := Build(t.Context(), Deps{Store: newServerTestStore(t), Log: openServerFederationSeamTestLog(t),
				ProviderHandlerFactory: func(*orchestrator.Orchestrator) (http.Handler, error) {
					if kind == "error" {
						return nil, failure
					}
					return nil, nil
				},
			})
			if srv != nil {
				_ = srv.Shutdown(context.Background())
			}
			if err == nil || (kind == "error" && !errors.Is(err, failure)) {
				t.Fatalf("incomplete factory allowed startup: %v", err)
			}
		})
	}
}

type providerFactoryLifecycleProjection struct {
	offboards int
	failure   error
}

func (*providerFactoryLifecycleProjection) Name() string                              { return "test.provider_factory_lifecycle" }
func (*providerFactoryLifecycleProjection) ProjectsTenantLifecycle()                  {}
func (*providerFactoryLifecycleProjection) Reset(context.Context) error               { return nil }
func (*providerFactoryLifecycleProjection) ResetTx(context.Context, pgx.Tx) error     { return nil }
func (*providerFactoryLifecycleProjection) Apply(context.Context, events.Event) error { return nil }
func (p *providerFactoryLifecycleProjection) ReplayTenantLifecycleTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	return p.ApplyTx(ctx, tx, e)
}
func (p *providerFactoryLifecycleProjection) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	if e.Type != projections.EventTenantOffboarded {
		return nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE tenant_id=$1)`, e.TenantID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return errors.New("test: lifecycle extension did not join the core erase")
	}
	p.offboards++
	return p.failure
}

func TestCorePendingTenantOffboardBlocksExistingCredential(t *testing.T) {
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "core-offboard-admin", Roles: []string{"admin"}})
	st := newServerTestStore(t)
	log := openServerFederationSeamTestLog(t)
	const tenantID = "e7dfcc41-2680-49f8-a877-49e48c1154b3"
	payload := []byte(`{"name":"Core pending erase"}`)
	registration, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projections.New(st), orchestrator.NewIdempotency(st),
		orchestrator.TenantRegistrationCommand{TenantID: tenantID, Name: "Core pending erase", IdempotencyKey: "core-pending-registration",
			RequestMaterial: payload, PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, tenantID, "owners:read", "owners:write")
	interrupted := errors.New("test: core erase interrupted")
	extension := &providerFactoryLifecycleProjection{failure: interrupted}
	// No Provider handler, factory, license, or tenant-service check is supplied.
	srv, err := Build(ctx, Deps{Store: st, Log: log, LicensedProjectionOptions: []projections.Option{projections.WithEventProjection(extension)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	read := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if got := read(); got != http.StatusOK {
		t.Fatalf("active credential=%d", got)
	}
	// A client-chosen key must not impersonate the durable core erase receiver
	// and deny service to the entire tenant.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/owners", strings.NewReader(`{"kind":"team","name":"Unprivileged key collision"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", store.TenantOffboardReceiverKeyPrefix+"tenant-offboard-f99220a4-2652-457f-a8d2-0f05b78d290c")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if got := read(); got != http.StatusOK {
		t.Fatalf("ordinary mutation key disabled service: mutation=%d subsequent read=%d", w.Code, got)
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("internal command namespace accepted from HTTP: %d %s", w.Code, w.Body.String())
	}
	command := orchestrator.TenantOffboardCommand{TenantID: tenantID, RegistrationIdentity: registration.ID}
	if _, err := srv.orch.OffboardTenant(ctx, command); !errors.Is(err, interrupted) {
		t.Fatalf("interrupted erase=%v", err)
	}
	if _, err := st.GetTenant(ctx, tenantID); err != nil {
		t.Fatalf("failed erase lost tenant: %v", err)
	}
	if got := read(); got != http.StatusForbidden {
		t.Fatalf("pending core erase admitted credential: %d", got)
	}
	extension.failure = nil
	if _, err := srv.orch.OffboardTenant(ctx, command); err != nil {
		t.Fatalf("recover erase: %v", err)
	}
	if got := read(); got != http.StatusUnauthorized {
		t.Fatalf("completed erase retained credential: %d", got)
	}
}

func TestProviderSurfaceIs404UnlessEditionHandlerIsAttached(t *testing.T) {
	core := newProviderSeamServer(t, nil)
	consoleReq := httptest.NewRequest(http.MethodGet, "/provider", nil)
	consoleRec := httptest.NewRecorder()
	core.handler.ServeHTTP(consoleRec, consoleReq)
	if consoleRec.Code != http.StatusOK || consoleRec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("provider console = %d content-type=%q, want embedded SPA", consoleRec.Code, consoleRec.Header().Get("Content-Type"))
	}
	coreReq := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants", nil)
	coreRec := httptest.NewRecorder()
	core.handler.ServeHTTP(coreRec, coreReq)
	if coreRec.Code != http.StatusNotFound {
		t.Fatalf("unlicensed provider surface = %d, want 404", coreRec.Code)
	}

	var saw bool
	licensed := newProviderSeamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = true
		if r.URL.Path != "/provider/v1/tenants" {
			t.Fatalf("provider handler path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	licensedReq := httptest.NewRequest(http.MethodGet, "/provider/v1/tenants", nil)
	licensedRec := httptest.NewRecorder()
	licensed.handler.ServeHTTP(licensedRec, licensedReq)
	if licensedRec.Code != http.StatusNoContent || !saw {
		t.Fatalf("licensed provider handler = %d saw=%t, want 204 and dispatch", licensedRec.Code, saw)
	}
}

func newProviderSeamServer(t *testing.T, provider http.Handler) *Server {
	t.Helper()
	bulk := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 1, Queue: 8})
	t.Cleanup(bulk.Close)
	s := &Server{
		bulk:      bulk,
		registry:  observ.NewRegistry(),
		tracer:    observ.NewTracer(nil),
		readiness: observ.NewReadiness(nil),
	}
	s.configureRootMux(Deps{ProviderHandler: provider}, api.New(nil, nil, nil))
	return s
}
