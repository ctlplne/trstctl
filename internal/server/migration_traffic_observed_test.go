// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

// X3-L2: a handshake counts at an endpoint's observed address (a backend
// behind NAT or a load balancer) and, with the endpoint's server name, on an
// observed address's port; never at an unrelated address.
func TestObservedHandshakeAtAnObservedAddressX3L2(t *testing.T) {
	t.Parallel()
	binding := migration.MemberBinding{VerifyAddress: "vip.example.test:443", VerifyServerName: "api.example.test",
		ObservedAddresses: []string{"10.0.3.17:8443"}}
	for _, c := range []struct {
		server, serverName string
		want               bool
	}{
		{"vip.example.test:443", "", true},
		{"10.0.3.17:8443", "", true},
		{"10.0.3.18:8443", "api.example.test", true}, // another backend on the observed port, same name
		{"10.0.3.18:443", "api.example.test", true},  // the verify address's port, same name
		{"10.0.3.18:8443", "other.example.test", false},
		{"10.0.9.9:9443", "api.example.test", false},
		{"10.0.3.17:9443", "", false},
	} {
		h := observedHandshake{Server: c.server, ServerName: c.serverName}
		if got := h.at(binding); got != c.want {
			t.Errorf("handshake at %s (%q) = %t, want %t", c.server, c.serverName, got, c.want)
		}
	}
	if (observedHandshake{Server: "10.0.3.17:8443"}).at(migration.MemberBinding{VerifyAddress: "vip.example.test:443"}) {
		t.Fatal("a binding without observed addresses matched a backend")
	}
}
