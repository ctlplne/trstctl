// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// protocols.acme_email is off when empty and otherwise needs a plain from
// address, lowercase mail domains, a profile and a relay (P15).
func TestValidateACMEEmailP15(t *testing.T) {
	if errs := validateACMEEmail(ACMEEmail{}); len(errs) != 0 {
		t.Fatalf("empty: %v", errs)
	}
	good := ACMEEmail{From: "acme@ca.example.com", Domains: []string{"example.com"}, Profile: "smime-signing", RelayAddr: "relay.example.com:587"}
	if errs := validateACMEEmail(good); len(errs) != 0 {
		t.Fatalf("good: %v", errs)
	}
	withAuth := good
	withAuth.RelayUsername, withAuth.RelayPasswordRef = "acme", "file:/run/secrets/relay"
	if errs := validateACMEEmail(withAuth); len(errs) != 0 {
		t.Fatalf("with relay auth: %v", errs)
	}
	for name, bad := range map[string]ACMEEmail{
		"display-name from":   {From: "CA <acme@ca.example.com>", Domains: []string{"example.com"}, Profile: "p", RelayAddr: "r:25"},
		"no domain":           {From: "acme@ca.example.com", Profile: "p", RelayAddr: "r:25"},
		"uppercase domain":    {From: "acme@ca.example.com", Domains: []string{"Example.com"}, Profile: "p", RelayAddr: "r:25"},
		"duplicate domain":    {From: "acme@ca.example.com", Domains: []string{"example.com", "example.com"}, Profile: "p", RelayAddr: "r:25"},
		"no profile":          {From: "acme@ca.example.com", Domains: []string{"example.com"}, RelayAddr: "r:25"},
		"relay without port":  {From: "acme@ca.example.com", Domains: []string{"example.com"}, Profile: "p", RelayAddr: "relay"},
		"username, no secret": {From: "acme@ca.example.com", Domains: []string{"example.com"}, Profile: "p", RelayAddr: "r:25", RelayUsername: "acme"},
	} {
		if errs := validateACMEEmail(bad); len(errs) == 0 {
			t.Fatalf("%s: accepted", name)
		}
	}
}
