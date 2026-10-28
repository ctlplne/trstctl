// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A207: a SCIM token's group map names each group, maps it to a well-formed
// role name, and maps at most one group to a role.
func TestSCIMGroupRolesNameGroupsAndOneGroupPerRole(t *testing.T) {
	token := func(groupRoles map[string]string) SCIMToken {
		return SCIMToken{Name: "okta", TenantID: "11111111-1111-1111-1111-111111111111", TokenFile: "/etc/trstctl/scim.token", GroupRoles: groupRoles} // #nosec G101 -- fixture file path, not a credential value (CWE-798)
	}
	ok := map[string]string{"payments-ops": "payments-operator", "Platform Admins": "admin"}
	if err := (SCIM{Enabled: true, Tokens: []SCIMToken{token(ok)}}).ValidateEnabled(); err != nil {
		t.Fatalf("a valid group map was refused: %v", err)
	}
	for name, tc := range map[string]struct {
		groupRoles map[string]string
		want       string
	}{
		"unnamed group":          {map[string]string{" ": "viewer"}, "a group name is 1 to 256 characters"},
		"long group":             {map[string]string{strings.Repeat("g", 257): "viewer"}, "a group name is 1 to 256 characters"},
		"malformed role":         {map[string]string{"payments-ops": "Payments Operator"}, "is not a role name"},
		"empty role":             {map[string]string{"payments-ops": ""}, "is not a role name"},
		"two groups to one role": {map[string]string{"payments-ops": "payments-operator", "payments-oncall": "payments-operator"}, "map one group per role"},
	} {
		err := SCIM{Enabled: true, Tokens: []SCIMToken{token(tc.groupRoles)}}.ValidateEnabled()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
