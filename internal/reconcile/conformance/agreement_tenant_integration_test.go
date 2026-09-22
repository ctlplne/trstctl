// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package conformance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/reconcile"
	reconcileapi "trstctl.com/trstctl/internal/reconcile/api"
)

// The caller produced this projection through PostgreSQL-backed collection,
// the isolated signer and the durable NATS log. Authentication here supplies
// fixture principals; it does not qualify a production identity provider.
func assertStoreBackedAgreementTenantBoundary(t *testing.T, h *e2eHarness, rt *reconcile.Runtime) {
	t.Helper()
	opts, err := reconcileapi.NewAPIOptionsFactory(rt.DriftProjection, rt.RoundsScheduledByTenant)(editionseam.LicensedAPIOptionsDeps{})
	if err != nil {
		t.Fatal(err)
	}
	role := authz.Role{Name: "agreement-reader", Permissions: []authz.Permission{authz.CertsRead}}
	var tenant string
	opts = append(opts, coreapi.WithRoles(role), coreapi.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) {
		return authz.Principal{TenantID: tenant, Subject: "agreement-reader", Grants: []authz.Grant{
			{Role: role, Scope: authz.Scope{TenantID: tenant}},
		}}, nil
	}))
	api := coreapi.New(h.store, orchestrator.NewIdempotency(h.store), nil, opts...)
	for _, scope := range []string{h.tenant, "00000000-0000-4000-8000-000000000002"} {
		tenant = scope
		res := httptest.NewRecorder()
		api.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/reconcile/agreement", nil))
		if res.Code != http.StatusOK {
			t.Fatalf("tenant %s: status=%d body=%s", tenant, res.Code, res.Body.String())
		}
		var report reconcileapi.AgreementReport
		if err := json.Unmarshal(res.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if tenant == h.tenant {
			if len(report.Authorities) != 2 || report.OpenWitnesses == 0 || !report.Collecting || report.ReplayWatermark == 0 {
				t.Fatalf("owner lost the real scheduled disagreement: %+v", report)
			}
			continue
		}
		if len(report.Authorities) != 0 || report.OpenWitnesses != 0 || report.ReplayWatermark != 0 ||
			report.Collecting || report.ResolvedInWindow != 0 || report.MedianResolutionSeconds != 0 {
			t.Fatalf("unrelated tenant received another tenant's durable agreement state: %+v", report)
		}
	}
}
