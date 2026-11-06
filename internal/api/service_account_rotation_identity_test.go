// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/servicedependents"
)

func TestDependentPreparedIdentityUsesNativeSIDRepresentationA267(t *testing.T) {
	account := servicedependents.AccountBinding{Name: "service", DN: "CN=service,DC=lab,DC=test", SID: "S-1-5-21-1-2-3-1001", GUID: strings.Repeat("a", 32)}
	native := "010500000000000515000000010000000200000003000000e9030000"
	if !dependentPreparedIdentityMatches(native, account.GUID, "cn=SERVICE,dc=LAB,dc=TEST", "service", account) {
		t.Fatal("same AD object rejected because preparation SID uses native bytes or DN has equivalent case")
	}
	for _, sid := range []string{account.SID, "010500000000000515000000010000000200000003000000ea030000", "00", strings.ToUpper(native)} {
		// This fixture contains no a-f hex letter except e; uppercase must stay
		// noncanonical, just like the retained native preparation parser.
		if dependentPreparedIdentityMatches(sid, account.GUID, account.DN, account.Name, account) {
			t.Fatal("substituted or noncanonical native SID accepted")
		}
	}
	if dependentPreparedIdentityMatches(native, strings.Repeat("b", 32), account.DN, account.Name, account) {
		t.Fatal("another native GUID accepted")
	}
}
