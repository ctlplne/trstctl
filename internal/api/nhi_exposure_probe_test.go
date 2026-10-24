// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

// A102: a posture endpoint maps to the host:port and server name a relay
// probes; one that names no knowable public listener is skipped.
func TestNHIExposureProbeAddress(t *testing.T) {
	for _, tc := range []struct {
		endpoint, address, serverName string
		ok                            bool
	}{
		{"https://api.example.com/v1/hook", "api.example.com:443", "api.example.com", true},
		{"https://API.example.com.:8443", "api.example.com:8443", "api.example.com", true},
		{"http://ci-token.example.com/api-key", "ci-token.example.com:80", "ci-token.example.com", true},
		{"wss://stream.example.com", "stream.example.com:443", "stream.example.com", true},
		{"api.example.com", "api.example.com:443", "api.example.com", true},
		{"api.example.com:9443", "api.example.com:9443", "api.example.com", true},
		{"203.0.113.10", "203.0.113.10:443", "", true},
		{"https://[2001:db8::10]:8443/x", "[2001:db8::10]:8443", "", true},
		{"ftp://files.example.com", "", "", false},
		{"https://10.0.0.5/hook", "", "", false},
		{"https://localhost:8443", "", "", false},
		{"svc.cluster.local:443", "", "", false},
		{"", "", "", false},
	} {
		address, serverName, ok := nhiExposureProbeAddress(tc.endpoint)
		if address != tc.address || serverName != tc.serverName || ok != tc.ok {
			t.Errorf("%q -> (%q, %q, %v); want (%q, %q, %v)", tc.endpoint, address, serverName, ok, tc.address, tc.serverName, tc.ok)
		}
	}
}

// A record is reachable when any endpoint answered the relay, not_public only
// when the relay refused every endpoint as non-public.
func TestNHIExposureReachabilityStatus(t *testing.T) {
	answered := nhiExposureReachabilityProbe{Outcome: "listener_without_tls", Reachable: true}
	refused := nhiExposureReachabilityProbe{Outcome: "not_public"}
	silent := nhiExposureReachabilityProbe{Outcome: "unreachable"}
	for _, tc := range []struct {
		endpoints []nhiExposureReachabilityProbe
		want      string
	}{
		{[]nhiExposureReachabilityProbe{silent, answered}, "reachable"},
		{[]nhiExposureReachabilityProbe{refused, refused}, "not_public"},
		{[]nhiExposureReachabilityProbe{refused, silent}, "unreachable"},
	} {
		if got := nhiExposureReachabilityStatus(tc.endpoints); got != tc.want {
			t.Errorf("status(%+v) = %q; want %q", tc.endpoints, got, tc.want)
		}
	}
}

// A probe takes endpoints in posture order, one per address per record, up to
// the bound, and counts what it left out.
func TestNHIExposureProbeEndpointsBoundAndDedupe(t *testing.T) {
	findings := []nhiExposurePostureFinding{
		{InventoryID: "a", PublicEndpoints: []string{"https://one.example.com", "one.example.com"}, CallbackURLs: []string{"https://cb.example.com/x"}},
		{InventoryID: "b", PublicEndpoints: []string{"https://one.example.com", "https://two.example.com"}},
	}
	got, omitted := nhiExposureProbeEndpoints(findings, 3)
	if len(got) != 3 || omitted != 1 || got[0].Address != "one.example.com:443" || got[1].Address != "cb.example.com:443" ||
		got[2].InventoryID != "b" || got[2].Address != "one.example.com:443" {
		t.Fatalf("endpoints=%+v omitted=%d", got, omitted)
	}
}
