// SPDX-License-Identifier: BUSL-1.1
package relay

import "testing"

func TestNativeCAConfigurationArgumentIsOneBoundedValueA267(t *testing.T) {
	for _, tc := range []struct {
		host, name string
		ok         bool
	}{
		{"ca.example.test", "Example Issuing CA", true},
		{"ca.example.test", "发行 CA", true},
		{"-config", "CA", false}, {"ca.example.test", "CA\\Other", false},
		{"ca.example.test", "CA\n-getreg", false}, {"ca.example.test", "CA\x00", false},
		{"ca.example.test\\Other", "CA", false},
		{"ca.example.test", "", false},
	} {
		_, ok := nativeCAConfigurationArgument(tc.host, tc.name)
		if ok != tc.ok {
			t.Fatalf("native CA configuration acceptance=%t want=%t", ok, tc.ok)
		}
	}
}
