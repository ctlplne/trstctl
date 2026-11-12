// SPDX-License-Identifier: BUSL-1.1

package est

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
)

// TestRequestIPUsesTheTrustedProxysClientM1L1: behind a load balancer in
// server.trusted_proxies, EST counts the client the server resolved from the
// balancer's X-Forwarded-For.
func TestRequestIPUsesTheTrustedProxysClientM1L1(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil)
	r.RemoteAddr = "198.51.100.20:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.8")
	proxies, err := netsec.ParseTrustedProxies([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	proxies.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = requestIP(r) })).ServeHTTP(httptest.NewRecorder(), r)
	if got != "203.0.113.8" {
		t.Fatalf("requestIP behind a trusted proxy = %s; want the forwarded client", got)
	}
}
