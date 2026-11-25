// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
)

func TestCR824RegisteredProjectScopeCoversNativeAndVaultKV(t *testing.T) {
	if testing.Short() {
		t.Skip("registered project scope needs real PostgreSQL and JetStream")
	}
	h := newMachineSessionHarness(t)
	status, body := h.do(t, http.MethodPost, "/api/v1/secrets/projects", msTenantA, "cr824-create-payments",
		map[string]any{"slug": "payments", "name": "Payments", "environments": []map[string]any{{"slug": "prod", "name": "Production"}}})
	if status != http.StatusCreated {
		t.Fatalf("create payments project: HTTP %d %s", status, body)
	}
	engine, err := policy.NewABAC(policy.ABACConfig{Module: `package trstctl.abac
default deny := false
default reason := ""
deny if { input.resource.project == "payments" }
reason := "payments closed" if { deny }
`})
	if err != nil {
		t.Fatal(err)
	}
	guarded := api.New(h.store, orchestrator.NewMemoryIdempotency(), nil,
		api.WithInsecureHeaderResolver(), api.WithABACDenyOverlay(engine, nil, nil))
	for _, path := range []string{
		"/api/v1/secrets/store/payments/prod/key",
		"/v1/secret/data/payments/prod/key",
		"/v1/secret/metadata/payments/prod/key",
	} {
		for _, header := range []string{"", "staging"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("X-Tenant-ID", msTenantA)
			req.Header.Set("X-Subject", "operator-1")
			req.Header.Set("X-Roles", "admin")
			if header != "" {
				req.Header.Set("X-Project", header)
			}
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "payments closed") {
				t.Errorf("GET %s with X-Project=%q: HTTP %d %s; want ABAC project denial", path, header, rec.Code, rec.Body.String())
			}
		}
	}
}
