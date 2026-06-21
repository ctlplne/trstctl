package privacy

// CatalogEntry records one class of personal data the product stores, why it is
// present, and how subject erasure handles it. Keeping this in code makes the
// API and docs tests share one machine-checkable inventory.
type CatalogEntry struct {
	ID             string `json:"id"`
	Location       string `json:"location"`
	Category       string `json:"category"`
	Purpose        string `json:"purpose"`
	RetentionClass string `json:"retention_class"`
	Erasure        string `json:"erasure"`
	Owner          string `json:"owner"`
}

// Catalog is the maintained personal-data inventory for privacy/API export.
func Catalog() []CatalogEntry {
	return []CatalogEntry{
		{
			ID:             "events.actor.subject",
			Location:       "events.Actor.Subject",
			Category:       "authenticated subject identifier",
			Purpose:        "audit attribution for state-changing operations",
			RetentionClass: "audit",
			Erasure:        "tenant audit reads replace erased subjects with subject_ref placeholders",
			Owner:          "platform",
		},
		{
			ID:             "events.data.subject-values",
			Location:       "events.Event.Data",
			Category:       "subject-linked payload values",
			Purpose:        "event-sourced rebuild of read models",
			RetentionClass: "audit",
			Erasure:        "privacy.subject.erased stores non-PII selectors; audit reads redact exact erased subject values",
			Owner:          "platform",
		},
		{
			ID:             "owners.email",
			Location:       "owners.email",
			Category:       "contact identifier",
			Purpose:        "credential ownership and notification metadata",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased blanks email and pseudonymizes name",
			Owner:          "identity inventory",
		},
		{
			ID:             "tenant_members.subject",
			Location:       "tenant_members.subject/display_name/email",
			Category:       "administrator subject and contact metadata",
			Purpose:        "RBAC membership and offboarding evidence",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased replaces subject with erased placeholder and clears display/contact fields",
			Owner:          "access control",
		},
		{
			ID:             "api_tokens.subject",
			Location:       "api_tokens.subject",
			Category:       "API-token principal subject",
			Purpose:        "token authentication and revocation metadata",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased revokes matching tokens and replaces subject with erased placeholder",
			Owner:          "access control",
		},
		{
			ID:             "identities.name-attributes",
			Location:       "identities.name/attributes",
			Category:       "workload or human-linked identity metadata",
			Purpose:        "credential lifecycle inventory",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased pseudonymizes selected identity names and clears attributes",
			Owner:          "identity inventory",
		},
		{
			ID:             "certificates.subject-sans",
			Location:       "certificates.subject/sans",
			Category:       "certificate subject alternative names",
			Purpose:        "certificate inventory, expiry, and risk analysis",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased pseudonymizes selected certificate subjects and clears SANs",
			Owner:          "certificate inventory",
		},
		{
			ID:             "ssh_keys.comment-location",
			Location:       "ssh_keys.comment/location",
			Category:       "SSH key descriptive metadata",
			Purpose:        "SSH trust inventory and drift analysis",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased clears selected comment and location fields",
			Owner:          "SSH trust",
		},
		{
			ID:             "attestations.evidence",
			Location:       "attestations.evidence",
			Category:       "free-form evidence payload",
			Purpose:        "policy and provenance evidence for credential actions",
			RetentionClass: "operational",
			Erasure:        "privacy.subject.erased clears selected evidence JSON",
			Owner:          "policy",
		},
	}
}
