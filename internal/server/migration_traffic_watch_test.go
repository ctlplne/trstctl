// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/migration"
)

// TestTrafficWatchKeepsExactlyTheWatchedHandshakesX3L4: the pass keeps a
// finding exactly when it was observed at one of the bindings it watches (the
// X3-L2 rule: an address, an observed address, or the server name on one of
// their ports), so filtering while paging never drops a deciding finding and
// keeps nothing else.
func TestTrafficWatchKeepsExactlyTheWatchedHandshakesX3L4(t *testing.T) {
	t.Parallel()
	bindings := []migration.MemberBinding{
		{VerifyAddress: "vip.example.test:443", VerifyServerName: "api.example.test", ObservedAddresses: []string{"10.0.3.17:8443"}},
		{VerifyAddress: "10.0.7.7:636"},
		{VerifyAddress: "", VerifyServerName: "nameless.example.test"},
	}
	watch := newTrafficWatch()
	for _, b := range bindings {
		watch.add(b)
	}
	handshakes := []observedHandshake{
		{Server: "vip.example.test:443"}, {Server: "10.0.3.17:8443"}, {Server: "10.0.3.18:8443", ServerName: "api.example.test"},
		{Server: "10.0.3.18:443", ServerName: "api.example.test"}, {Server: "10.0.3.18:8443", ServerName: "other.example.test"},
		{Server: "10.0.9.9:9443", ServerName: "api.example.test"}, {Server: "10.0.3.17:9443"}, {Server: "10.0.7.7:636"},
		{Server: "10.0.7.8:636"}, {Server: "10.0.7.8:636", ServerName: "nameless.example.test"}, {Server: "not-an-address", ServerName: "api.example.test"},
		{Server: ""},
	}
	kept := 0
	for _, h := range handshakes {
		want := false
		for _, b := range bindings {
			want = want || h.at(b)
		}
		if got := watch.watches(h); got != want {
			t.Errorf("handshake at %q (%q): kept=%t, want %t", h.Server, h.ServerName, got, want)
		}
		if want {
			kept++
		}
	}
	if kept != 5 {
		t.Fatalf("the cases keep %d handshakes, want 5 (the table drifted)", kept)
	}
	if newTrafficWatch().watches(observedHandshake{Server: "vip.example.test:443"}) {
		t.Fatal("an empty watch kept a handshake")
	}
}
