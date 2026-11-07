// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import "testing"

func TestADRecoveryValidationNeedsExactLocalDocumentA267(t *testing.T) {
	const dn = "CN=service,OU=services,DC=example,DC=test"
	for name, raw := range map[string][]byte{
		"malformed":        []byte(`{"password":`),
		"wrong target":     []byte(`{"bind_dn":"CN=other,DC=example,DC=test","password":"Owned1!retained-generation"}`),
		"invalid recovery": []byte(`{"bind_dn":"CN=service,OU=services,DC=example,DC=test","password":"tiny"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if ValidateADRecoveryCredential(raw, dn) == nil {
				t.Fatal("unrecoverable predecessor accepted")
			}
		})
	}
	if err := ValidateADRecoveryCredential([]byte(`{"bind_dn":"cn=SERVICE,ou=services,dc=example,dc=test","password":"Owned1!retained-generation"}`), dn); err != nil {
		t.Fatal(err)
	}
}
