// SPDX-License-Identifier: BUSL-1.1
package adcs

// EnrollmentEndpointBeforeProbe is the exact endpoint wire shape in inventory
// observations v2/v3. Never widen it when adding current probing evidence.
type EnrollmentEndpointBeforeProbe struct {
	Kind               EnrollmentEndpointKind  `json:"kind"`
	URL                string                  `json:"url"`
	State              EnrollmentEndpointState `json:"state"`
	HTTPStatus         int                     `json:"http_status,omitempty"`
	Authentication     []string                `json:"authentication,omitempty"`
	TLSVerified        bool                    `json:"tls_verified"`
	ExtendedProtection EvidenceState           `json:"extended_protection"`
}
type EnrollmentServiceBeforeProbe struct {
	Name                  string                          `json:"name"`
	DNSName               string                          `json:"dns_name,omitempty"`
	Templates             []string                        `json:"templates,omitempty"`
	EnrollmentWebServices []string                        `json:"enrollment_web_services,omitempty"`
	Endpoints             []EnrollmentEndpointBeforeProbe `json:"endpoints,omitempty"`
	AgentRestrictions     EnrollmentAgentRestrictions     `json:"agent_restrictions"`
}

// TemplateBeforeEndpointProbe freezes the v3 addition without reusing the
// active Template, whose later fields must never widen historical payloads.
type TemplateBeforeEndpointProbe struct {
	TemplateBeforeMembership
	EnrollmentACL        *EnrollmentACL        `json:"enrollment_acl,omitempty"`
	EnrollmentMembership *EnrollmentMembership `json:"enrollment_membership,omitempty"`
}

const InventoryMembershipSchemaVersion = 3

type InventoryObservedV3 struct {
	MembershipDomainDN  string                         `json:"membership_domain_dn,omitempty"`
	NestedGroupsEnabled bool                           `json:"nested_groups_enabled,omitempty"`
	RunID               string                         `json:"run_id"`
	SourceID            string                         `json:"source_id"`
	Domain              string                         `json:"domain"`
	AgentID             string                         `json:"agent_id"`
	AgentName           string                         `json:"agent_name"`
	DirectoryVerified   bool                           `json:"directory_verified"`
	Templates           []TemplateBeforeEndpointProbe  `json:"templates"`
	EnrollmentServices  []EnrollmentServiceBeforeProbe `json:"enrollment_services"`
	Findings            []Finding                      `json:"findings"`
}

func UpconvertEnrollmentServices(old []EnrollmentServiceBeforeProbe) []EnrollmentService {
	out := make([]EnrollmentService, 0, len(old))
	for _, service := range old {
		current := EnrollmentService{Name: service.Name, DNSName: service.DNSName, Templates: service.Templates, EnrollmentWebServices: service.EnrollmentWebServices, AgentRestrictions: service.AgentRestrictions}
		for _, endpoint := range service.Endpoints {
			current.Endpoints = append(current.Endpoints, EnrollmentEndpoint{Kind: endpoint.Kind, URL: endpoint.URL, State: endpoint.State, HTTPStatus: endpoint.HTTPStatus, Authentication: endpoint.Authentication, TLSVerified: endpoint.TLSVerified, ExtendedProtection: endpoint.ExtendedProtection})
		}
		out = append(out, current)
	}
	return out
}
func (old InventoryObservedV3) Current() InventoryObserved {
	templates := make([]Template, 0, len(old.Templates))
	for _, template := range old.Templates {
		current := UpconvertTemplates([]TemplateBeforeMembership{template.TemplateBeforeMembership})[0]
		current.EnrollmentACL = template.EnrollmentACL
		current.EnrollmentMembership = template.EnrollmentMembership
		templates = append(templates, current)
	}
	return InventoryObserved{MembershipDomainDN: old.MembershipDomainDN, NestedGroupsEnabled: old.NestedGroupsEnabled, RunID: old.RunID, SourceID: old.SourceID, Domain: old.Domain, AgentID: old.AgentID, AgentName: old.AgentName, DirectoryVerified: old.DirectoryVerified, Templates: templates, EnrollmentServices: UpconvertEnrollmentServices(old.EnrollmentServices), Findings: old.Findings}
}
