// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
	"time"
)

func TestADAccountStatePreventsUnsafePasswordBinds(t *testing.T) {
	good := map[string][]string{"sAMAccountName": {"service"}, "userAccountControl": {"512"}, "msDS-User-Account-Control-Computed": {"0"}, "badPwdCount": {"0"}, "pwdLastSet": {"1"}, "accountExpires": {"0"}}
	if name, err := validateADAccountState(ldap.NewEntry("CN=service", good), true, time.Now()); err != nil || name != "service" {
		t.Fatalf("valid state: %s %v", name, err)
	}
	for attr, bad := range map[string][]string{"sAMAccountName": {"", "bad\nname"}, "userAccountControl": {"514", "not-a-number"}, "msDS-User-Account-Control-Computed": {"16", "8388608"}, "badPwdCount": {"1", "-1"}, "pwdLastSet": {"0"}, "accountExpires": {"1", "18446744073709551615"}} {
		for _, value := range bad {
			candidate := map[string][]string{}
			for k, v := range good {
				candidate[k] = v
			}
			candidate[attr] = []string{value}
			if _, err := validateADAccountState(ldap.NewEntry("CN=service", candidate), true, time.Now()); err == nil {
				t.Fatalf("unsafe %s=%q accepted", attr, value)
			}
		}
	}
	for _, attr := range []string{"userAccountControl", "msDS-User-Account-Control-Computed", "badPwdCount", "pwdLastSet"} {
		candidate := map[string][]string{}
		for k, v := range good {
			candidate[k] = v
		}
		delete(candidate, attr)
		if _, err := validateADAccountState(ldap.NewEntry("CN=service", candidate), true, time.Now()); err == nil {
			t.Fatalf("missing %s accepted", attr)
		}
	}
}
func TestADModeRefusesAuthorityChangesBeforeNetwork(t *testing.T) {
	cfg := LDAPConfig{DirectoryMode: "active_directory", Addr: "directory.example:636", TLSServerName: "directory.example", BindDN: "CN=admin,DC=example,DC=test", BindPassword: []byte("owned-test-administrator"), UsersDN: "OU=services,DC=example,DC=test", RoleGroups: map[string]string{"service": "CN=service,OU=services,DC=example,DC=test"}}
	backend, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if _, _, err = backend.CreateCredential(context.Background(), GenerateRequest{Role: "service", Static: true, Predecessor: "CN=foreign,OU=services,DC=example,DC=test"}); err == nil {
		t.Fatal("foreign predecessor allowed")
	}
	if _, _, err = backend.CreateCredential(context.Background(), GenerateRequest{Role: "unknown", Static: true}); err == nil {
		t.Fatal("foreign role allowed")
	}
	if _, _, err = backend.Create(context.Background(), "service"); err == nil {
		t.Fatal("dynamic AD user issuance invented")
	}
	if err = backend.Revoke(context.Background(), "CN=foreign,OU=services,DC=example,DC=test"); err == nil {
		t.Fatal("foreign account retirement allowed")
	}
	for _, mode := range []string{"unknown", strings.Repeat("a", 1024)} {
		bad := cfg
		bad.DirectoryMode = mode
		if b, e := NewLDAPBackend(bad); e == nil {
			b.Close()
			t.Fatal("unknown directory mode accepted")
		}
	}
	bad := cfg
	bad.AllowPlaintext = true
	bad.TLSServerName = ""
	bad.Addr = "127.0.0.1:389"
	if b, e := NewLDAPBackend(bad); e == nil {
		b.Close()
		t.Fatal("AD plaintext allowed")
	}
}
