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
		{raw: "fips-140", want: api.ComplianceFIPS140},
		{raw: "fips-140-3", want: api.ComplianceFIPS140},
		{raw: "fips", want: api.ComplianceFIPS140},
		{raw: "common-criteria", want: api.ComplianceCommonCriteria},
		{raw: "cc", want: api.ComplianceCommonCriteria},
		{raw: "iso-15408", want: api.ComplianceCommonCriteria},
		{raw: "nist-800-53", want: api.ComplianceNIST80053},
		{raw: "nist-sp-800-53", want: api.ComplianceNIST80053},
		{raw: "nist-csf-2.0", want: api.ComplianceNISTCSF20},
		{raw: "csf", want: api.ComplianceNISTCSF20},
		{raw: "cmmc-2.0", want: api.ComplianceCMMC20},
		{raw: "cmmc", want: api.ComplianceCMMC20},
		{raw: "eidas", want: api.ComplianceEIDAS},
		{raw: "eidas-2.0", want: api.ComplianceEIDAS},
		{raw: "nis2", want: api.ComplianceNIS2},
		{raw: "nis-2", want: api.ComplianceNIS2},
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

func TestFIPSComplianceFrameworkAliasesResolveToEvidencePackFramework(t *testing.T) {
	for _, raw := range []string{"fips-140", "fips-140-2", "fips-140-3", "fips140", "fips"} {
		got, err := api.ParseComplianceFramework(raw)
		if err != nil {
			t.Fatalf("ParseComplianceFramework(%q): %v", raw, err)
		}
		if got != api.ComplianceFIPS140 {
			t.Fatalf("ParseComplianceFramework(%q) = %q, want %q", raw, got, api.ComplianceFIPS140)
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
