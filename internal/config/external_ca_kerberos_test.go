// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// An AD CS Kerberos setting without a keytab used to be ignored without a
// word: the CA authenticated with Basic and the realm, principal, KDCs or SPN
// the operator wrote had no effect.
func TestADCSKerberosSettingsNeedAKeytab(t *testing.T) {
	base := ExternalCAConfig{ID: "a", Type: "adcs", Name: "a", Endpoint: "https://adcs.example/certsrv", CAConfig: `HOST\CA`, Template: "WebServer"}
	for field, set := range map[string]func(*ExternalCAConfig){
		"kerberos_realm":     func(c *ExternalCAConfig) { c.KerberosRealm = "CORP.EXAMPLE" },
		"kerberos_principal": func(c *ExternalCAConfig) { c.KerberosPrincipal = "svc-trstctl" },
		"kerberos_kdcs":      func(c *ExternalCAConfig) { c.KerberosKDCs = []string{"dc1.corp.example:88"} },
		"kerberos_spn":       func(c *ExternalCAConfig) { c.KerberosSPN = "HTTP/adcs.corp.example" },
	} {
		item := base
		set(&item)
		err := ValidateExternalCAs([]ExternalCAConfig{item})
		if err == nil || !strings.Contains(err.Error(), field+" is set without kerberos_keytab_ref") {
			t.Errorf("%s without a keytab: %v; want it refused by name", field, err)
		}
	}
	if err := ValidateExternalCAs([]ExternalCAConfig{base}); err != nil {
		t.Fatalf("Basic AD CS without any Kerberos setting: %v", err)
	}
}
