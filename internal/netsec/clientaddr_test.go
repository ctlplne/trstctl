// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientAddrReadsForwardedForOnlyFromTrustedProxiesM1L1 pins how the
// client behind a request is resolved: a peer that is not a trusted proxy is
// the client whatever X-Forwarded-For says; behind a trusted proxy it is the
// right-most forwarded address that is not itself a trusted proxy, so a
// client's own entries to the left are ignored; a header that cannot be read
// whole is not used.
func TestClientAddrReadsForwardedForOnlyFromTrustedProxiesM1L1(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8", " 192.0.2.7 ", "2001:db8:1::/48"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"untrusted peer, no header", "198.51.100.20:5000", nil, "198.51.100.20"},
		{"untrusted peer names another client", "198.51.100.20:5000", []string{"203.0.113.7"}, "198.51.100.20"},
		{"trusted proxy forwards the client", "10.1.2.3:443", []string{"203.0.113.7"}, "203.0.113.7"},
		{"a client's own entry is ignored", "10.1.2.3:443", []string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"two trusted hops", "10.1.2.3:443", []string{"203.0.113.7, 192.0.2.7"}, "203.0.113.7"},
		{"header lines are joined in order", "10.1.2.3:443", []string{"1.2.3.4", "203.0.113.8, 10.9.9.9"}, "203.0.113.8"},
		{"every hop trusted: the left-most", "10.1.2.3:443", []string{"10.4.4.4, 10.5.5.5"}, "10.4.4.4"},
		{"trusted proxy, no header", "10.1.2.3:443", nil, "10.1.2.3"},
		{"unreadable header", "10.1.2.3:443", []string{"203.0.113.7, not-an-address"}, "10.1.2.3"},
		{"IPv6 behind a trusted IPv6 proxy", "[2001:db8:1::5]:443", []string{"2001:db8:9::1"}, "2001:db8:9::1"},
		{"IPv4-mapped peer", "[::ffff:10.1.2.3]:443", []string{"203.0.113.9"}, "203.0.113.9"},
		{"too many hops", "10.1.2.3:443", []string{strings.Repeat("203.0.113.1, ", maxForwardedHops) + "203.0.113.2"}, "10.1.2.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got, _ := proxies.ClientAddr(r); got.String() != tc.want {
				t.Fatalf("ClientAddr = %s, want %s", got, tc.want)
			}
			var seen string
			proxies.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = ClientIP(r) })).ServeHTTP(httptest.NewRecorder(), r)
			if seen != tc.want {
				t.Fatalf("ClientIP behind the middleware = %s, want %s", seen, tc.want)
			}
		})
	}
	// With no trusted proxies a forwarded-for header is never read.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got, _ := (TrustedProxies{}).ClientAddr(r); got.String() != "10.1.2.3" {
		t.Fatalf("no trusted proxies: ClientAddr = %s", got)
	}
	// Without the middleware, ClientIP is the peer.
	if got := ClientIP(r); got != "10.1.2.3" {
		t.Fatalf("ClientIP without the middleware = %s", got)
	}
}

// TestParseTrustedProxiesRefusesEveryAddressM1L1: a prefix matching every
// address would let any client name its own address; junk is refused.
func TestParseTrustedProxiesRefusesEveryAddressM1L1(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/33", "load-balancer", "10.0.0.0/8/2"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("ParseTrustedProxies(%q) accepted", bad)
		}
	}
	if p, err := ParseTrustedProxies([]string{"", "  "}); err != nil || len(p.prefixes) != 0 {
		t.Fatalf("blank entries = %v, %v", p.prefixes, err)
	}
}
