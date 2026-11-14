// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// P15-L2: trstctl's own DKIM signing names a selector and a key reference
// together; the selector is lowercase DNS labels and the key a file: or
// secret:// reference.
func TestACMEEmailDKIMSigningSettingsP15L2(t *testing.T) {
	base := ACMEEmail{From: "acme@ca.example.test", Domains: []string{"example.test"}, Profile: "smime", RelayAddr: "relay.example.test:25"}
	good := base
	good.DKIMSelector, good.DKIMKeyRef = "trstctl.2026", "secret://dkim/challenge-key"
	if errs := validateACMEEmail(good); len(errs) != 0 {
		t.Fatalf("a selector and a secret:// key = %v", errs)
	}
	for name, mutate := range map[string]func(*ACMEEmail){
		"a selector without a key": func(p *ACMEEmail) { p.DKIMSelector = "trstctl" },
		"a key without a selector": func(p *ACMEEmail) { p.DKIMKeyRef = "file:/etc/trstctl/dkim.pem" },
		"an uppercase selector":    func(p *ACMEEmail) { p.DKIMSelector, p.DKIMKeyRef = "Trstctl", "file:/etc/trstctl/dkim.pem" },
		"a selector with a space":  func(p *ACMEEmail) { p.DKIMSelector, p.DKIMKeyRef = "trst ctl", "file:/etc/trstctl/dkim.pem" },
		"an inline key":            func(p *ACMEEmail) { p.DKIMSelector, p.DKIMKeyRef = "trstctl", "an inline key, not a reference" },
	} {
		bad := base
		mutate(&bad)
		if errs := validateACMEEmail(bad); len(errs) == 0 {
			t.Fatalf("%s was accepted", name)
		}
	}
}
