// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A malformed id in any uuid-typed path parameter is a bad request, never an
// internal error: the guard runs before the handler so a uuid-typed store query
// never receives a non-uuid string. A well-formed but absent id still resolves
// to 404 (DP2-047).
func TestServedMalformedUUIDPathIDsAreBadRequestsEverywhere(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "identities:read", "identities:write", "owners:read", "certs:read")

	routes := []struct {
		method string
		tmpl   string
		body   map[string]any
	}{
		{http.MethodGet, "/api/v1/identities/%s", nil},
		{http.MethodPost, "/api/v1/identities/%s/transitions", map[string]any{"to": "issued", "reason": "malformed id probe"}},
		{http.MethodGet, "/api/v1/owners/%s", nil},
		{http.MethodGet, "/api/v1/certificates/%s", nil},
	}
	for _, rt := range routes {
		for _, id := range []string{"None", "not-a-uuid", "12345"} {
			status, body := secretsReq(t, h, rt.method, fmt.Sprintf(rt.tmpl, id), tok, rt.body)
			if status != http.StatusBadRequest {
				t.Errorf("%s %s (id=%q) = %d body %s, want 400", rt.method, rt.tmpl, id, status, body)
			}
		}
		status, body := secretsReq(t, h, rt.method, fmt.Sprintf(rt.tmpl, "00000000-0000-4000-8000-000000000000"), tok, rt.body)
		if status != http.StatusNotFound {
			t.Errorf("%s %s (absent uuid) = %d body %s, want 404", rt.method, rt.tmpl, status, body)
		}
	}
}
