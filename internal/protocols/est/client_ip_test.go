// SPDX-License-Identifier: BUSL-1.1

package est

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequestIPNeverReadsAClientsForwardedForM1L1: EST counts failed
// authentication attempts per client, so the client must not choose its own
// address: a client's X-Forwarded-For is ignored.
func TestRequestIPNeverReadsAClientsForwardedForM1L1(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil)
	r.RemoteAddr = "198.51.100.20:5000"
	for _, claimed := range []string{"203.0.113.7", "203.0.113.8"} {
		r.Header.Set("X-Forwarded-For", claimed)
		if got := requestIP(r); got != "198.51.100.20" {
			t.Fatalf("requestIP with a client's X-Forwarded-For %s = %s; want the peer", claimed, got)
		}
	}
}
