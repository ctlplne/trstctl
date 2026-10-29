// SPDX-License-Identifier: BUSL-1.1
package api

func adcsEnrollmentACLSchema() *Schema {
	return object(map[string]*Schema{
		"allowed": {Type: "array", Items: &Schema{Type: "string"}, MaxItems: 1024}, "denied": {Type: "array", Items: &Schema{Type: "string"}, MaxItems: 1024}, "unassessed_aces": {Type: "integer"},
	}, "allowed", "denied", "unassessed_aces")
}
func adcsMembershipNodeSchema() *Schema {
	return object(map[string]*Schema{
		"sid": {Type: "string"}, "dn": {Type: "string"}, "kind": {Type: "string", Enum: []string{"group", "user", "computer"}}, "parents": {Type: "array", Items: &Schema{Type: "string"}, MaxItems: 64}, "security_group": {Type: "boolean"},
	}, "sid", "dn", "kind")
}
func adcsEnrollmentTrusteeSchema() *Schema {
	return object(map[string]*Schema{
		"sid": {Type: "string"}, "dn": {Type: "string"}, "state": {Type: "string", Enum: []string{"complete", "unresolved", "read_failed", "invalid_identity", "non_security_group", "membership_unconfirmed", "incomplete_search", "incomplete_attributes", "ambiguous_identity", "matching_rule_unconfirmed"}}, "positive_control": {Type: "boolean"}, "direct_member_dns": {Type: "array", Items: &Schema{Type: "string"}, MaxItems: 1024}, "nodes": {Type: "array", Items: ref("ADCSMembershipNode"), MaxItems: 1025},
	}, "sid", "state", "positive_control")
}
func adcsEnrollmentMemberSchema() *Schema {
	return object(map[string]*Schema{
		"sid": {Type: "string"}, "dn": {Type: "string"}, "kind": {Type: "string", Enum: []string{"user", "computer"}}, "via_trustees": {Type: "array", Items: &Schema{Type: "string"}}, "path": {Type: "array", Items: &Schema{Type: "string"}, MaxItems: 16},
	}, "sid", "dn", "kind", "via_trustees", "path")
}
func adcsEnrollmentMembershipSchema() *Schema {
	return object(map[string]*Schema{
		"state": {Type: "string", Enum: []string{"complete", "incomplete"}}, "domain_dn": {Type: "string"}, "matching_rule": {Type: "string", Enum: []string{"1.2.840.113556.1.4.1941"}}, "observed_at": {Type: "string", Format: "date-time"}, "trustees": {Type: "array", Items: ref("ADCSEnrollmentTrustee")}, "members": {Type: "array", Items: ref("ADCSEnrollmentMember")}, "limitations": {Type: "array", Items: &Schema{Type: "string"}}, "budget_exceeded": {Type: "boolean"},
	}, "state", "domain_dn", "matching_rule", "observed_at", "trustees", "members", "limitations")
}
