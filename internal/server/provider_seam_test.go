// SPDX-License-Identifier: MPL-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/observ"
)

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
