// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	decapi "trstctl.com/trstctl/internal/decommission/api"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCoreVDECMutationsReachValidationAfterCommercialLicenseExpires(t *testing.T) {
	opts, err := decapi.NewAPIOptionsFactory()(editionseam.LicensedAPIOptionsDeps{})
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts,
		api.WithLicense(expiredLicenseManager(t)),
		api.WithInsecureHeaderResolver(),
		api.WithRoles(authz.Role{Name: "vdec-operator", Permissions: []authz.Permission{authz.KeysWrite}}),
	)
	served := api.New(nil, orchestrator.NewMemoryIdempotency(), nil, opts...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/keys/qa-root/retirement", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "vdec-core-expired-license")
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Subject", "qa-operator")
	req.Header.Set("X-Roles", "vdec-operator")
	res := httptest.NewRecorder()
	served.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || strings.Contains(res.Body.String(), "commercial license") {
		t.Fatalf("Core VDEC validation after commercial expiry = %d %s, want 400 invalid JSON", res.Code, res.Body.String())
	}
}
