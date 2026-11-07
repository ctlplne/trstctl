// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"errors"
	"slices"
	"testing"
)

// TestNetDeviceOperationsA270: a device command's first word names the
// operations it abbreviates, so an abbreviation cannot slip past a rule;
// read-only commands name nothing; every line of a multi-line exec counts;
// a rule for the netdevice protocol takes only device operations.
func TestNetDeviceOperationsA270(t *testing.T) {
	for raw, want := range map[string][]string{
		"show running-config":                {},
		"sh run | include username":          {},
		"get system status":                  {},
		"write memory":                       {"write"},
		"wr":                                 {"write"},
		"conf t":                             {"configure"},
		"co":                                 {"commit", "configure", "copy"},
		"do write memory":                    {"write"},
		"show version\nreload in 5":          {"reload"},
		"request system reboot":              {"request"},
		"execute reboot":                     {"execute"},
		"save sys config":                    {"save"},
		"Configure Terminal":                 {"configure"},
		"s":                                  {},
		"start shell":                        {"start"},
		"copy running-config startup-config": {"copy"},
		"modify auth user ops password secret-pw": {"modify"},
	} {
		got, err := NetDeviceOperations([]byte(raw))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("NetDeviceOperations(%q) = %v %v, want %v", raw, got, err, want)
		}
	}
	if _, err := NetDeviceOperations([]byte("write\x00memory")); !errors.Is(err, ErrUninspectable) {
		t.Fatal("a NUL byte was inspected")
	}
	if _, err := NetDeviceOperations([]byte("wr\x1b[A")); !errors.Is(err, ErrUninspectable) {
		t.Fatal("a control sequence was inspected")
	}
	rules, err := CanonicalRules([]Rule{{ID: "6f1f1b8e-5b0e-4b8e-9e27-0b0d5f6b1a01", Name: "No saves", Enabled: true, Protocol: "netdevice", Operations: []string{"WRITE", "reload"}, Effect: EffectBlock}})
	if err != nil || len(rules) != 1 || !slices.Equal(rules[0].Operations, []string{"reload", "write"}) {
		t.Fatalf("netdevice rule = %+v %v", rules, err)
	}
	if _, err := CanonicalRules([]Rule{{ID: "6f1f1b8e-5b0e-4b8e-9e27-0b0d5f6b1a02", Name: "Shell verb", Enabled: true, Protocol: "netdevice", Operations: []string{"rm"}, Effect: EffectBlock}}); err == nil {
		t.Fatal("a shell operation was accepted for the netdevice protocol")
	}
}
