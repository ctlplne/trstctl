// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A profile-scoped caller must not make admission see tls-dev while the handler
// acts on tls-prod. The same ambiguity applies to profile writes using "name".
func TestCR832ProfileCaseVariantCannotChangeAuthorizedIssueTarget(t *testing.T) {
	role := authz.Role{Name: "profile-issuer", Permissions: []authz.Permission{authz.CertsIssue}}
	service := &boundExternalCAService{}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithExternalCAs(service))
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3, 4}}))
	send := func(key, fields string) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"csr_pem":` + strconv.Quote(csr) + `,"dns_names":["svc.example.test"],` + fields + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/external-cas/ca-one/issue", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
		req.Header.Set("X-Subject", "dev-issuer")
		req.Header.Set("X-Roles", "profile-issuer")
		req.Header.Set("X-Role-Profile", "tls-dev")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	control := send("cr832-control", `"profile_name":"tls-dev"`)
	if control.Code != http.StatusCreated || service.last.ProfileName != "tls-dev" {
		t.Fatalf("valid scoped issue: status=%d profile=%q body=%s", control.Code, service.last.ProfileName, control.Body.String())
	}
	calls := service.calls
	for i, fields := range []string{
		`"profile_name":"tls-dev","PROFILE_NAME":"tls-prod"`,
		`"profile_name":"tls-dev","Profile_Name":"tls-prod"`,
		`"profile_name":"tls-dev","profile_name":"tls-prod"`,
	} {
		rec := send("cr832-variant-"+strconv.Itoa(i), fields)
		if rec.Code != http.StatusBadRequest || service.calls != calls {
			t.Errorf("ambiguous profile %s: status=%d calls=%d, want 400 and %d calls: %s", fields, rec.Code, service.calls, calls, rec.Body.String())
		}
	}
}

func TestCR832ProfileWriteScopeRejectsCaseVariant(t *testing.T) {
	for _, body := range []string{
		`{"name":"tls-dev","NAME":"tls-prod","spec":{}}`,
		`{"name":"tls-dev","name":"tls-prod","spec":{}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/profiles", strings.NewReader(body))
		if _, err := scopeProfileJSON("name")(req); err == nil {
			t.Errorf("ambiguous profile write scope accepted: %s", body)
		}
	}
}
