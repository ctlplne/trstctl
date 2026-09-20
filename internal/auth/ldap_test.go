// SPDX-License-Identifier: BUSL-1.1

package auth

import "testing"

func TestLDAPTemplateEscapesFilterPlaceholders(t *testing.T) {
	got := ldapTemplate(
		"(&(uid={username})(member={user_dn}))",
		`alice*)(\admin`,
		`uid=alice*)(\admin,ou=people,dc=example,dc=org`,
	)
	want := `(&(uid=alice\2a\29\28\5cadmin)(member=uid=alice\2a\29\28\5cadmin,ou=people,dc=example,dc=org))`
	if got != want {
		t.Fatalf("ldapTemplate() = %q, want %q", got, want)
	}
}
