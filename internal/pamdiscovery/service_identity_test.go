// SPDX-License-Identifier: BUSL-1.1
package pamdiscovery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeADServiceIdentityDoesNotInventPrivilegeA267(t *testing.T) {
	account := Account{Key: "user:service", Name: "service", Kind: KindDirectoryServiceAccount, Details: map[string]string{"dn": "CN=service,DC=lab,DC=test", "native_guid": strings.Repeat("a", 32), "native_sid": "S-1-5-21-1-2-3-1001", "service_account": "true", "configured_rotation_account": "true"}}
	if err := ValidateDiscoveredAccount(account); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dn", "native_guid", "native_sid", "service_account", "configured_rotation_account"} {
		value := account.Details[key]
		delete(account.Details, key)
		if err := ValidateDiscoveredAccount(account); err == nil {
			t.Fatal("incomplete service identity admitted", key)
		}
		account.Details[key] = value
	}
	for _, kind := range []string{KindDirectoryUser, KindLocalUser, KindDatabaseRole, KindDatabaseUser, KindSQLLogin} {
		account.Kind = kind
		if err := ValidateDiscoveredAccount(account); err == nil {
			t.Fatal("existing privileged account validation was weakened", kind)
		}
	}
}

func FuzzNativeADServiceIdentitySelectionA267(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("{\"dn\":\"CN=service,DC=lab,DC=test\",\"native_guid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"native_sid\":\"S-1-5-21-1-2-3-1001\",\"service_account\":\"true\",\"configured_rotation_account\":\"true\"}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32768 {
			return
		}
		var details map[string]string
		if json.Unmarshal(raw, &details) != nil {
			return
		}
		account := Account{Key: "user:service", Name: "service", Kind: KindDirectoryServiceAccount, Details: details}
		if err := ValidateDiscoveredAccount(account); err == nil {
			if details["service_account"] != "true" || len(details["native_guid"]) != 32 || !strings.HasPrefix(details["native_sid"], "S-1-5-21-") {
				t.Fatal("incomplete native service identity accepted")
			}
			account.Kind = KindDirectoryUser
			if ValidateDiscoveredAccount(account) == nil {
				t.Fatal("service evidence replaced privilege evidence for an existing kind")
			}
		}
	})
}
