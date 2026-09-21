// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqcmigration"
)

func TestCorePQCMigrationKeepsValidationAfterCommercialLicenseExpires(t *testing.T) {
	for _, tc := range []struct {
		name    string
		manager *license.Manager
	}{
		{"community", license.Community()},
		{"expired", expiredLicenseManager(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := pqcmigration.NewAPIOptionsFactory(pqcmigration.NewProgressProjection(nil))(editionseam.LicensedAPIOptionsDeps{})
			if err != nil {
				t.Fatal(err)
			}
			opts = append(opts, api.WithLicense(tc.manager), api.WithInsecureHeaderResolver(),
				api.WithRoles(authz.Role{Name: "issuer", Permissions: []authz.Permission{authz.CertsIssue}},
					authz.Role{Name: "reader", Permissions: []authz.Permission{authz.CertsRead}}))
			h := api.New(nil, orchestrator.NewMemoryIdempotency(), nil, opts...)
			for _, path := range []string{"/api/v1/pqc/migrations", "/api/v1/pqc/migrations/run-1/rollback"} {
				t.Run(path, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"asset_ids":[]}`))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Idempotency-Key", tc.name+path)
					req.Header.Set("X-Tenant-ID", "tenant-r13")
					req.Header.Set("X-Subject", "operator-r13")
					req.Header.Set("X-Roles", "issuer")
					res := httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "asset_ids must contain at least one CBOM asset") {
						t.Fatalf("Core PQC validation = %d %s, want 400 asset validation regardless of commercial license state", res.Code, res.Body.String())
					}
					req = req.Clone(req.Context())
					req.Header.Set("X-Roles", "reader")
					res = httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusForbidden || strings.Contains(res.Body.String(), "commercial license") {
						t.Fatalf("Core PQC reader = %d %s, want authorization denial", res.Code, res.Body.String())
					}
					req.Header.Set("X-Roles", "issuer")
					req.Header.Del("Idempotency-Key")
					res = httptest.NewRecorder()
					h.ServeHTTP(res, req)
					if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "Idempotency-Key") {
						t.Fatalf("Core PQC without retry key = %d %s, want missing-key rejection", res.Code, res.Body.String())
					}
				})
			}
		})
	}
}
