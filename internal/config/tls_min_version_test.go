// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

func TestServerTLSMinVersionDefaultsToThirteenAndAcceptsOnlyKnownFloors(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{{"", false}, {"1.3", false}, {"1.2", true}, {" 1.2 ", true}} {
		if got := (TLS{MinVersion: tc.raw}).AllowsTLS12(); got != tc.want {
			t.Errorf("MinVersion %q -> AllowsTLS12 %v, want %v", tc.raw, got, tc.want)
		}
	}
	c := Default()
	c.Server.TLS.MinVersion = "1.1"
	if err := c.Validate(); err == nil {
		t.Fatal("server.tls.min_version 1.1 must be rejected")
	}
	c.Server.TLS.MinVersion = "1.2"
	if err := c.Validate(); err != nil {
		t.Fatalf("server.tls.min_version 1.2 must validate: %v", err)
	}
}
