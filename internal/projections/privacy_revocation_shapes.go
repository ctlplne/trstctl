// SPDX-License-Identifier: BUSL-1.1
package projections

import "trstctl.com/trstctl/internal/revocationhealth"

// Keep the v1 LDAP binding closed. A directory trust pin is a new public
// command field, not a reason to reinterpret previously accepted events.
type privacyRevocationLDAPBindingV1 struct {
	SourceID           string `json:"source_id"`
	URL                string `json:"url"`
	ConfigurationDN    string `json:"configuration_dn"`
	BindDN             string `json:"bind_dn"`
	PasswordRef        string `json:"password_ref"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

type privacyRevocationProbeV1 struct {
	ID                 string                          `json:"id"`
	Bucket             string                          `json:"bucket"`
	BatchIndex         int                             `json:"batch_index"`
	BatchCount         int                             `json:"batch_count"`
	Targets            []revocationhealth.Target       `json:"targets"`
	StaleWithinSeconds int                             `json:"stale_within_seconds"`
	RequiredAgentRole  string                          `json:"required_agent_role"`
	RequiredAgentID    string                          `json:"required_agent_id,omitempty"`
	LDAPBinding        *privacyRevocationLDAPBindingV1 `json:"ldap_binding,omitempty"`
	Endpoints          []string                        `json:"endpoints,omitempty"`
	IssuerDER          []byte                          `json:"issuer_der,omitempty"`
}

const RevocationDirectoryTLSQueuedSchemaVersion = 2
