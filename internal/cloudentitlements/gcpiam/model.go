// SPDX-License-Identifier: BUSL-1.1
// Package gcpiam captures selected workload service-account metadata. Policy
// bindings and observed audit use are evidence, never an effective-access grant.
package gcpiam

import "time"

const SourceKind = "gcp_machine_identity"
const FindingKind = "gcp_machine_identity"

type Config struct {
	Project                 string   `json:"project"`
	ServiceAccounts         []string `json:"service_accounts"`
	TokenFileRef            string   `json:"token_file_ref"`
	IAMEndpoint             string   `json:"iam_endpoint,omitempty"`
	ResourceManagerEndpoint string   `json:"resource_manager_endpoint,omitempty"`
	LoggingEndpoint         string   `json:"logging_endpoint,omitempty"`
	ActivityLookbackDays    int      `json:"activity_lookback_days,omitempty"`
	CAPEM                   string   `json:"ca_pem,omitempty"`
	AllowPrivateEndpoint    bool     `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs      []string `json:"private_egress_cidrs,omitempty"`
}
type Identity struct {
	Name        string `json:"name"`
	Project     string `json:"projectId"`
	NativeID    string `json:"uniqueId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName,omitempty"`
	Disabled    bool   `json:"disabled"`
}
type Condition struct {
	Title       string `json:"title,omitempty"`
	Expression  string `json:"expression,omitempty"`
	Description string `json:"description,omitempty"`
	Location    string `json:"location,omitempty"`
}
type Binding struct {
	Role      string     `json:"role"`
	Members   []string   `json:"members"`
	Condition *Condition `json:"condition,omitempty"`
}
type Policy struct {
	Version  int       `json:"version"`
	ETag     string    `json:"etag"`
	Bindings []Binding `json:"bindings"`
}
type RoleBinding struct {
	Role               string     `json:"role"`
	Scope              string     `json:"scope"`
	Condition          *Condition `json:"condition,omitempty"`
	Permissions        []string   `json:"permissions"`
	PermissionCoverage string     `json:"permission_coverage"`
	PolicyETag         string     `json:"policy_etag"`
}
type Key struct {
	Name            string     `json:"name"`
	Type            string     `json:"keyType"`
	Origin          string     `json:"keyOrigin"`
	ValidAfter      time.Time  `json:"validAfterTime"`
	ValidBefore     time.Time  `json:"validBeforeTime"`
	Disabled        bool       `json:"disabled"`
	AgeDays         int        `json:"age_days"`
	LongLived       bool       `json:"long_lived"`
	LastObservedUse *time.Time `json:"last_observed_use_at,omitempty"`
	LastUseCoverage string     `json:"last_use_coverage"`
}
type Inventory struct {
	Version           int           `json:"version"`
	Provider          string        `json:"provider"`
	SourceOrigin      string        `json:"source_origin"`
	SourceFingerprint string        `json:"source_fingerprint"`
	CollectedAt       time.Time     `json:"collected_at"`
	Identity          Identity      `json:"identity"`
	Keys              []Key         `json:"keys"`
	KeysCoverage      string        `json:"keys_coverage"`
	TrustPolicy       Policy        `json:"trust_policy"`
	TrustCoverage     string        `json:"trust_coverage"`
	PolicyBindings    []RoleBinding `json:"policy_bindings"`
	PolicyCoverage    string        `json:"policy_coverage"`
	ActivityStart     *time.Time    `json:"activity_window_start,omitempty"`
	ActivityEnd       *time.Time    `json:"activity_window_end,omitempty"`
	ActivityCoverage  string        `json:"activity_coverage"`
	Limitations       []string      `json:"limitations"`
	RiskScore         int           `json:"risk_score"`
}
