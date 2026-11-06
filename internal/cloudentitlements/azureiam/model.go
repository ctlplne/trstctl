// SPDX-License-Identifier: BUSL-1.1
// Package azureiam captures selected Azure workload identities and native policy
// metadata. It never infers effective access from incomplete native bindings.
package azureiam

import "time"

const SourceKind = "azure_machine_identity"
const FindingKind = SourceKind

type Config struct {
	TenantID                 string            `json:"azure_tenant_id"`
	SubscriptionID           string            `json:"subscription_id"`
	PrincipalIDs             []string          `json:"service_principal_ids"`
	GraphTokenFileRef        string            `json:"graph_token_file_ref"`
	ARMTokenFileRef          string            `json:"arm_token_file_ref"`
	GraphEndpoint            string            `json:"graph_endpoint,omitempty"`
	ARMEndpoint              string            `json:"arm_endpoint,omitempty"`
	ReadBetaSignins          bool              `json:"read_beta_signins,omitempty"`
	ActivityLookbackDays     int               `json:"activity_lookback_days,omitempty"`
	ManagedIdentityResources map[string]string `json:"managed_identity_resources,omitempty"`
	CAPEM                    string            `json:"ca_pem,omitempty"`
	AllowPrivateEndpoint     bool              `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs       []string          `json:"private_egress_cidrs,omitempty"`
}
type Credential struct {
	ID              string     `json:"keyId"`
	Start           time.Time  `json:"startDateTime"`
	End             time.Time  `json:"endDateTime"`
	Kind            string     `json:"kind"`
	AgeDays         int        `json:"age_days"`
	LongLived       bool       `json:"long_lived"`
	LastObservedUse *time.Time `json:"last_observed_use_at,omitempty"`
	LastUseCoverage string     `json:"last_use_coverage"`
}
type Identity struct {
	ID        string       `json:"id"`
	AppID     string       `json:"appId"`
	Name      string       `json:"displayName"`
	Type      string       `json:"servicePrincipalType"`
	Enabled   bool         `json:"accountEnabled"`
	Keys      []Credential `json:"keyCredentials"`
	Passwords []Credential `json:"passwordCredentials"`
}
type AppRole struct {
	ID                 string   `json:"id"`
	PrincipalID        string   `json:"principalId"`
	ResourceID         string   `json:"resourceId"`
	RoleID             string   `json:"appRoleId"`
	Value              string   `json:"value,omitempty"`
	AllowedMemberTypes []string `json:"allowed_member_types,omitempty"`
	Enabled            bool     `json:"enabled"`
	Coverage           string   `json:"definition_coverage"`
}
type Federation struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Audiences []string `json:"audiences"`
}
type Permission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}
type RoleAssignment struct {
	ID         string `json:"id"`
	Properties struct {
		PrincipalID      string `json:"principalId"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		Scope            string `json:"scope"`
		Condition        string `json:"condition"`
		ConditionVersion string `json:"conditionVersion"`
	} `json:"properties"`
	Permissions        []Permission `json:"permissions"`
	DefinitionCoverage string       `json:"definition_coverage"`
}
type Inventory struct {
	Version                 int              `json:"version"`
	Provider                string           `json:"provider"`
	TenantID                string           `json:"azure_tenant_id"`
	SubscriptionID          string           `json:"subscription_id"`
	SourceOrigin            string           `json:"source_origin"`
	SourceFingerprint       string           `json:"source_fingerprint"`
	CollectedAt             time.Time        `json:"collected_at"`
	Identity                Identity         `json:"identity"`
	AppRoles                []AppRole        `json:"app_roles"`
	AppRoleCoverage         string           `json:"app_role_coverage"`
	Federation              []Federation     `json:"federation"`
	FederationCoverage      string           `json:"federation_coverage"`
	RBAC                    []RoleAssignment `json:"rbac"`
	RBACCoverage            string           `json:"rbac_coverage"`
	ManagedIdentityResource string           `json:"managed_identity_resource,omitempty"`
	ManagedIdentityCoverage string           `json:"managed_identity_coverage"`
	ActivityStart           *time.Time       `json:"activity_window_start,omitempty"`
	ActivityEnd             *time.Time       `json:"activity_window_end,omitempty"`
	ActivityCoverage        string           `json:"activity_coverage"`
	Limitations             []string         `json:"limitations"`
	RiskScore               int              `json:"risk_score"`
}
