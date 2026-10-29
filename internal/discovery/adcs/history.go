// SPDX-License-Identifier: BUSL-1.1
package adcs

// TemplateBeforeMembership is the exact template shape used in event versions
// one and two. Never add current fields here: old privacy/import schemas stay closed.
type TemplateBeforeMembership struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	OID         string `json:"oid,omitempty"`
	// SchemaVersion 1 templates cannot express many of the modern controls at
	// all — they have no enrollment flags an admin can tighten — so a v1
	// template with a client-auth EKU is a different conversation from a v4 one.
	SchemaVersion int `json:"schema_version,omitempty"`
	// EnrolleeSuppliesSubject and EnrolleeSuppliesSAN are the two flags that
	// turn a template into an impersonation primitive.
	EnrolleeSuppliesSubject bool `json:"enrollee_supplies_subject"`
	EnrolleeSuppliesSAN     bool `json:"enrollee_supplies_san"`
	// RequiresManagerApproval is the control that makes the above survivable.
	RequiresManagerApproval bool `json:"requires_manager_approval"`
	// ExportableKey means the private key can leave the machine it was issued to.
	ExportableKey bool `json:"exportable_key"`
	// EKUs are the extended key usages, by OID.
	EKUs []string `json:"ekus,omitempty"`
	// EnrollmentPrincipals are the security principals granted enrollment
	// rights, as the directory reports them. Who can use a dangerous template
	// is most of how dangerous it is.
	EnrollmentPrincipals []string `json:"enrollment_principals,omitempty"`
	// PublishedBy names the enrollment services (CAs) that offer this template.
	// A dangerous template nobody publishes is a latent risk; one published by
	// an issuing CA is a live one.
	PublishedBy []string `json:"published_by,omitempty"`
}

// InventoryObservedV1 is the historical template-only wire payload.
type InventoryObservedV1 struct {
	RunID             string                     `json:"run_id"`
	SourceID          string                     `json:"source_id"`
	Domain            string                     `json:"domain"`
	AgentID           string                     `json:"agent_id"`
	AgentName         string                     `json:"agent_name"`
	DirectoryVerified bool                       `json:"directory_verified"`
	Templates         []TemplateBeforeMembership `json:"templates"`
	Findings          []Finding                  `json:"findings"`
}

// InventoryObservedV2 adds service evidence while retaining the frozen templates.
type InventoryObservedV2 struct {
	RunID              string                     `json:"run_id"`
	SourceID           string                     `json:"source_id"`
	Domain             string                     `json:"domain"`
	AgentID            string                     `json:"agent_id"`
	AgentName          string                     `json:"agent_name"`
	DirectoryVerified  bool                       `json:"directory_verified"`
	Templates          []TemplateBeforeMembership `json:"templates"`
	EnrollmentServices []EnrollmentService        `json:"enrollment_services"`
	Findings           []Finding                  `json:"findings"`
}

func UpconvertTemplates(legacy []TemplateBeforeMembership) []Template {
	out := make([]Template, 0, len(legacy))
	for _, old := range legacy {
		out = append(out, Template{Name: old.Name, DisplayName: old.DisplayName, OID: old.OID, SchemaVersion: old.SchemaVersion, EnrolleeSuppliesSubject: old.EnrolleeSuppliesSubject, EnrolleeSuppliesSAN: old.EnrolleeSuppliesSAN, RequiresManagerApproval: old.RequiresManagerApproval, ExportableKey: old.ExportableKey, EKUs: old.EKUs, EnrollmentPrincipals: old.EnrollmentPrincipals, PublishedBy: old.PublishedBy})
	}
	return out
}
func (old InventoryObservedV1) Current() InventoryObserved {
	return InventoryObserved{RunID: old.RunID, SourceID: old.SourceID, Domain: old.Domain, AgentID: old.AgentID, AgentName: old.AgentName, DirectoryVerified: old.DirectoryVerified, Templates: UpconvertTemplates(old.Templates), Findings: old.Findings}
}
func (old InventoryObservedV2) Current() InventoryObserved {
	return InventoryObserved{RunID: old.RunID, SourceID: old.SourceID, Domain: old.Domain, AgentID: old.AgentID, AgentName: old.AgentName, DirectoryVerified: old.DirectoryVerified, Templates: UpconvertTemplates(old.Templates), EnrollmentServices: old.EnrollmentServices, Findings: old.Findings}
}
