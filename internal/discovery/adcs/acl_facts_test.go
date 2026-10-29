// SPDX-License-Identifier: BUSL-1.1
package adcs_test

import (
	"reflect"
	"testing"
	"trstctl.com/trstctl/internal/discovery/adcs"
)

func TestEnrollmentACLFactsPreserveDeniesBeforeNestedExpansion(t *testing.T) {
	const group = "S-1-5-21-111-222-333-1001"
	const blocked = "S-1-5-21-111-222-333-1002"
	deny := allowACE(0x100, sidBytes(blocked))
	deny[0] = 0x01
	allowBlocked := allowACE(0x100, sidBytes(blocked))
	descriptor := securityDescriptor(allowACE(0x100, sidBytes(group)), allowBlocked, deny)
	facts, err := adcs.EnrollmentACLFromSecurityDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facts.Allowed, []string{group, blocked}) || !reflect.DeepEqual(facts.Denied, []string{blocked}) {
		t.Fatalf("nested expansion lost raw grant/deny authority: %+v", facts)
	}
	direct, err := adcs.EnrollmentPrincipalsFromSecurityDescriptor(descriptor)
	if err != nil || !reflect.DeepEqual(direct, []string{group}) {
		t.Fatalf("historical exact-SID deny behavior changed: %v %v", direct, err)
	}
}
func TestEnrollmentACLDoesNotClaimConditionalACECompleteness(t *testing.T) {
	conditional := allowACE(0x100, sidBytes("S-1-5-11"))
	conditional[0] = 0x0a
	facts, err := adcs.EnrollmentACLFromSecurityDescriptor(securityDescriptor(conditional))
	if err != nil {
		t.Fatal(err)
	}
	if facts.UnassessedACEs != 1 || len(facts.Allowed) != 0 {
		t.Fatalf("conditional permission was guessed: %+v", facts)
	}
}
