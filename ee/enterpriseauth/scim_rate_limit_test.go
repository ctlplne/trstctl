// SPDX-License-Identifier: LicenseRef-trstctl-EE
package enterpriseauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

func TestSpecialSCIMUsersRouteRateLimitedSEC002(t *testing.T) {
	token := "scim-secret"
	h := api.New(nil, nil, nil,
		api.WithSCIM(api.SCIMConfig{Enabled: true, NewHandler: NewSCIMHandler, Tokens: []api.SCIMToken{{
			Name:      "okta",
			TenantID:  "11111111-1111-4111-8111-111111111111",
			TokenHash: crypto.SHA256Hex([]byte(token)),
		}}}),
		api.WithSpecialRouteAbuseLimits(api.SpecialRouteAbuseLimits{
			Window:            time.Minute,
			Global:            10,
			PerSource:         10,
			PerToken:          1,
			PerTenant:         10,
			PreLoginGlobal:    10,
			PreLoginPerSource: 10,
		}),
	)

	body := []byte(`{"userName":"alice@example.test","active":true}`)
	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(body))
	firstReq.RemoteAddr = "203.0.113.40:1234"
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstReq.Header.Set("Content-Type", "application/scim+json")
	firstReq.Header.Set("Idempotency-Key", "scim-first")
	h.ServeHTTP(first, firstReq)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("first POST /scim/v2/Users = %d, want 503 from missing store after budget check", first.Code)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(body))
	secondReq.RemoteAddr = "203.0.113.41:1234"
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondReq.Header.Set("Content-Type", "application/scim+json")
	secondReq.Header.Set("Idempotency-Key", "scim-second")
	h.ServeHTTP(second, secondReq)
	assertSpecialTooManyRequests(t, second, "POST /scim/v2/Users")
}

func assertSpecialTooManyRequests(t *testing.T, rec *httptest.ResponseRecorder, route string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s over budget = %d, want 429: %s", route, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatalf("%s over budget missing Retry-After", route)
	}
}
