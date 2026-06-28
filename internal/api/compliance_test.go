package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestParseComplianceFrameworkAcceptsCAAuditPostureFrameworks(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want api.ComplianceFramework
	}{
		{raw: "webtrust", want: api.ComplianceWebTrust},
		{raw: "web-trust", want: api.ComplianceWebTrust},
		{raw: "webtrust-ca", want: api.ComplianceWebTrust},
		{raw: "etsi", want: api.ComplianceETSI},
		{raw: "etsi-en-319-411", want: api.ComplianceETSI},
		{raw: "etsi-en-319-411-2", want: api.ComplianceETSI},
		{raw: "cabf-br", want: api.ComplianceCABFBR},
		{raw: "cabf", want: api.ComplianceCABFBR},
		{raw: "ca-browser-forum-br", want: api.ComplianceCABFBR},
	} {
		got, err := api.ParseComplianceFramework(tc.raw)
		if err != nil {
			t.Fatalf("ParseComplianceFramework(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("ParseComplianceFramework(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

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
