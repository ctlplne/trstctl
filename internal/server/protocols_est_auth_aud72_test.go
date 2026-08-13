// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedESTBearerChallengeAUD72(t *testing.T) {
	h := newServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})

	request := func(authorization string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/.well-known/est/simpleenroll", strings.NewReader("not-a-csr"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/pkcs10")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	assertDenied := func(authorization string, status int, challenge string) {
		t.Helper()
		resp := request(authorization)
		if resp.StatusCode != status {
			t.Fatalf("Authorization %q status = %d, want %d", authorization, resp.StatusCode, status)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != challenge {
			t.Fatalf("Authorization %q challenge = %q, want %q", authorization, got, challenge)
		}
	}

	assertDenied("", http.StatusUnauthorized, `Bearer realm="est", scope="certs:request"`)
	assertDenied("Basic ZGV2aWNlOnBhc3N3b3Jk", http.StatusBadRequest,
		`Bearer realm="est", error="invalid_request", scope="certs:request"`)
	assertDenied("Bearer trst_invalid", http.StatusUnauthorized,
		`Bearer realm="est", error="invalid_token", scope="certs:request"`)

	readOnlyToken := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"certs:read"})
	assertDenied("Bearer "+readOnlyToken, http.StatusForbidden,
		`Bearer realm="est", error="insufficient_scope", scope="certs:request"`)

	requestToken := seedAPIToken(t, h.store, servedTestTenant)
	for _, credential := range []string{
		requestToken,
		base64.StdEncoding.EncodeToString([]byte(requestToken)), // pinned libest token wrapper
	} {
		authorized := request("Bearer " + credential)
		if authorized.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorized malformed CSR status = %d, want parser-owned 400", authorized.StatusCode)
		}
		if got := authorized.Header.Get("WWW-Authenticate"); got != "" {
			t.Fatalf("authorized request received authentication challenge %q", got)
		}
	}
}
