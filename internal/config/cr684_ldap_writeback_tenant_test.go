// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestCR684LDAPWritebackRefusesSharedDirectoryAcrossTenants(t *testing.T) {
	l := LDAP{
		Enabled: true, URL: "ldap://127.0.0.1:389", UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: "/run/secrets/ldap-bind",
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn",
		SessionSecretFile: "/run/secrets/ldap-session", SessionTTL: "1h",
		Writeback: LDAPWriteback{Enabled: true, BaseDN: "dc=example,dc=org", RoleGroups: map[string]string{
			"admin": "cn=trstctl-admins,ou=groups,dc=example,dc=org",
		}},
		TenantMappings: []TenantMapping{
			{Group: "trstctl-admins", TenantID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Roles: []string{"admin"}},
			{Group: "team-b", TenantID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Roles: []string{"admin"}},
		},
	}
	if err := l.ValidateEnabled(); err == nil || !strings.Contains(err.Error(), "writeback") || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("shared writeback validation = %v, want multiple-tenants refusal", err)
	}
	l.TenantMappings[1].TenantID = l.TenantMappings[0].TenantID
	if err := l.ValidateEnabled(); err != nil {
		t.Fatalf("one tenant with two login groups refused: %v", err)
	}
	l.AllowDefaultTenant = true
	l.DefaultTenant = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if err := l.ValidateEnabled(); err == nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("different default tenant bypassed writeback refusal: %v", err)
	}
	l.AllowDefaultTenant = false
	l.NestedGroups.Enabled = true
	l.NestedGroups.Mode = LDAPNestedGroupsRecursive
	l.TenantMappings[1].TenantID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if err := l.ValidateEnabled(); err == nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("nested role groups bypassed writeback refusal: %v", err)
	}
	l.Writeback.Enabled = false
	if err := l.ValidateEnabled(); err != nil {
		t.Fatalf("read-only LDAP login for two tenants refused: %v", err)
	}
}
