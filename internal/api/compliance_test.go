package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestComplianceEvidencePackRouteIsHiddenWhenUnlicensed(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unlicensed compliance evidence-pack status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}
