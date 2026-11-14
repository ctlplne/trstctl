// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// P15-L6: pinned SPF records name lowercase domains and hold SPF records.
func TestACMEEmailSPFSettingsP15L6(t *testing.T) {
	base := ACMEEmail{From: "acme@ca.example.test", Domains: []string{"example.test"}, Profile: "smime", RelayAddr: "relay.example.test:25"}
	good := base
	good.RequireSPF, good.SPFRecords = true, map[string]string{"example.test": "v=spf1 ip4:192.0.2.0/24 -all", "bare.example.test": "v=spf1"}
	if errs := validateACMEEmail(good); len(errs) != 0 {
		t.Fatalf("pinned SPF records = %v", errs)
	}
	for name, records := range map[string]map[string]string{
		"an uppercase domain": {"Example.test": "v=spf1 -all"},
		"not an SPF record":   {"example.test": "v=DKIM1; p=abc"},
		"a v=spf10 record":    {"example.test": "v=spf10 -all"},
	} {
		bad := base
		bad.SPFRecords = records
		if errs := validateACMEEmail(bad); len(errs) == 0 {
			t.Fatalf("%s was accepted", name)
		}
	}
}
