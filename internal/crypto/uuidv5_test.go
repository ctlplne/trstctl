// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

func TestUUIDv5OIDMatchesRetainedEventIdentity(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"managed-ca-legacy-inventory\x0011111111-1111-4111-8111-111111111111\x00mint-17", "23f9147b-04e0-53f2-a106-04943c29731c"},
		{"secret-pki-inventory\x0011111111-1111-4111-8111-111111111111\x00mint-17", "5f7b35b1-11ba-591d-8710-fa42b5eae2ec"},
	} {
		if got := UUIDv5OID([]byte(tc.name)); got != tc.want {
			t.Errorf("UUIDv5OID(%q) = %s, want %s", tc.name, got, tc.want)
		}
	}
}
