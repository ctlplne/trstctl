// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

// privacyDiscoveryRunQueued is the closed union carried by
// discovery.run.queued. The projector reads the embedded common relay fields;
// AD CS boot reconciliation additionally needs its immutable public connection
// command. PasswordRef is a reference name, never credential material.
type privacyDiscoveryRunQueued struct {
	segmentscan.Intent
	URL                string `json:"url,omitempty"`
	ConfigurationDN    string `json:"configuration_dn,omitempty"`
	BindDN             string `json:"bind_dn,omitempty"`
	PasswordRef        string `json:"password_ref,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	// The AD CS command also carries its bounded enrollment-endpoint checks and
	// private-egress policy; all three are public target descriptions.
	EnrollmentEndpoints  []adcsdiscovery.EnrollmentEndpointTarget `json:"enrollment_endpoints,omitempty"`
	AllowPrivateEndpoint bool                                     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string                                 `json:"private_egress_cidrs,omitempty"`
}

// DiscoveryEnrollmentGroupsQueuedSchemaVersion adds explicit domain membership
// scope. The historical v1 union above stays closed.
const DiscoveryEnrollmentGroupsQueuedSchemaVersion = 2

type privacyDiscoveryEnrollmentGroupsQueued struct {
	privacyDiscoveryRunQueued
	NestedGroupsEnabled bool   `json:"nested_groups_enabled,omitempty"`
	MembershipDomainDN  string `json:"membership_domain_dn,omitempty"`
}

// The row's anchor is derived only by the projector, never accepted in a relay
// report or added to the immutable Template wire shape.
func adcsProjectionObservationID(template adcsdiscovery.Template, eventID string) string {
	if template.EnrollmentMembership != nil {
		return eventID
	}
	return ""
}
