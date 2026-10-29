// SPDX-License-Identifier: BUSL-1.1
package api

func adcsEndpointProbeSourceSchema() *Schema {
	return &Schema{Type: "string", Enum: []string{"configured", "ldap_dns", "configured_and_ldap_dns"}}
}
func adcsEndpointProbeCoverageSchema() *Schema {
	return object(map[string]*Schema{
		"plan_digest":   {Type: "string", MinLength: 64, MaxLength: 64},
		"state":         {Type: "string", Enum: []string{"in_page", "not_in_page", "host_unassessed"}},
		"reason":        {Type: "string", Enum: []string{"invalid_directory_hostname", "outside_configured_dns_suffixes"}},
		"total_targets": {Type: "integer"}, "offset": {Type: "integer"}, "next_offset": {Type: "integer"}, "targets_on_page": {Type: "integer"},
		"complete": {Type: "boolean", Description: "True only when the whole directory plan fits in this page without hostname issues. Individual HTTP outcomes may still be unverified."},
	}, "plan_digest", "state", "total_targets", "offset", "next_offset", "targets_on_page", "complete")
}
func adcsEndpointProbeTargetSchema() *Schema {
	return object(map[string]*Schema{"enrollment_service": str(), "kind": {Type: "string", Enum: []string{"web_enrollment", "ndes", "ndes_admin"}}, "url": str(), "source": adcsEndpointProbeSourceSchema()}, "enrollment_service", "kind", "url", "source")
}
func adcsEndpointProbePageSchema() *Schema {
	return object(map[string]*Schema{
		"plan_digest": {Type: "string", MinLength: 64, MaxLength: 64}, "total_targets": {Type: "integer"}, "offset": {Type: "integer"}, "next_offset": {Type: "integer"}, "complete": {Type: "boolean"},
		"targets":     {Type: "array", Items: ref("ADCSEndpointProbeTarget"), MaxItems: 24},
		"host_issues": {Type: "array", MaxItems: 512, Items: object(map[string]*Schema{"enrollment_service": str(), "reason": {Type: "string", Enum: []string{"invalid_directory_hostname", "outside_configured_dns_suffixes"}}}, "enrollment_service", "reason")},
	}, "plan_digest", "total_targets", "offset", "next_offset", "complete", "targets", "host_issues")
}
