// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"testing"
)

// A malformed discovery id in the path is a bad request, not an internal error:
// a uuid-typed store query must never receive a non-uuid string. A well-formed
// but absent id still resolves to 404.
func TestServedDiscoveryMalformedPathIDsAreBadRequests(t *testing.T) {
	h := newDiscoveryRelayHarness(t, "loopback-idcheck")
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	for _, tmpl := range []string{"/api/v1/discovery/sources/%s/preflight", "/api/v1/discovery/runs/%s"} {
		for _, id := range []string{"None", "not-a-uuid", "12345"} {
			status, body := secretsReq(t, h.servedHarness, http.MethodGet, fmt.Sprintf(tmpl, id), tok, nil)
			if status != http.StatusBadRequest {
				t.Errorf("GET %s (id=%q) = %d body %s, want 400", tmpl, id, status, body)
			}
		}
		status, _ := secretsReq(t, h.servedHarness, http.MethodGet, fmt.Sprintf(tmpl, "00000000-0000-4000-8000-000000000000"), tok, nil)
		if status != http.StatusNotFound {
			t.Errorf("GET %s (absent uuid) = %d, want 404", tmpl, status)
		}
	}
}
