// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCR684LDAPWritebackAttachmentRefusesMultipleTenants(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "ldap-bind.secret")
	if err := os.WriteFile(passwordFile, []byte("fixture-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := config.LDAP{
		Enabled: true, URL: "ldap://127.0.0.1:389", UserDNTemplate: "uid={username},ou=people,dc=example,dc=org",
		BindDN: "cn=admin,dc=example,dc=org", BindPasswordFile: passwordFile,
		GroupSearchBaseDN: "ou=groups,dc=example,dc=org", GroupFilter: "(member={user_dn})", GroupNameAttribute: "cn",
		SessionSecretFile: filepath.Join(t.TempDir(), "ldap-session.secret"), SessionTTL: "1h",
		Writeback: config.LDAPWriteback{Enabled: true, BaseDN: "dc=example,dc=org", RoleGroups: map[string]string{
			"admin": "cn=trstctl-admins,ou=groups,dc=example,dc=org",
		}},
		TenantMappings: []config.TenantMapping{
			{Group: "trstctl-admins", TenantID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Roles: []string{"admin"}},
			{Group: "team-b", TenantID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Roles: []string{"admin"}},
		},
	}
	attachment, err := buildLDAPWritebackConfig(l)
	if err == nil || attachment != nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("multi-tenant writeback attachment = %v, err %v; want startup refusal", attachment, err)
	}
}

func TestCR684LDAPWritebackDeliveryRefusesSharedTargetsBeforeDirectoryAccess(t *testing.T) {
	const group = "cn=trstctl-admins,ou=groups,dc=example,dc=org"
	shared := ldapWritebackTarget{URL: "ldap://127.0.0.1:389", RoleGroups: map[string]string{"admin": group}}
	w := newLDAPWriteback(api.LDAPWritebackDeps{}, map[string]ldapWritebackTarget{
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": shared,
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb": shared,
	})
	payload, err := json.Marshal(orchestrator.LDAPWritebackIntent{Subject: "uid=bob,ou=people,dc=example,dc=org"})
	if err != nil {
		t.Fatal(err)
	}
	err = w.Deliver(context.Background(), orchestrator.Message{
		TenantID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Payload: payload,
	})
	if err == nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("shared writeback delivery error = %v, want refusal before any directory access", err)
	}
}
