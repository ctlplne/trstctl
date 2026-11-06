// SPDX-License-Identifier: BUSL-1.1
// Package assessment joins captured machine policies to explicitly scoped
// activity evidence. Its results are advisory, never mutation authority.
package assessment

import (
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

const SourceKind = "cloud_machine_entitlement"
const FindingKind = "cloud_machine_entitlement"

type PolicySet struct {
	Coverage  awspolicy.Coverage `json:"coverage"`
	Documents []json.RawMessage  `json:"documents,omitempty"`
}

// Supplemental contains imported evidence unavailable from the IAM API. Its
// source is always displayed as operator-supplied recorded evidence.
type Supplemental struct {
	PrincipalARN      string             `json:"principal_arn"`
	SourceRef         string             `json:"source_ref"`
	Resource          string             `json:"resource"`
	ResourceAccountID string             `json:"resource_account_id"`
	ResourcePolicies  PolicySet          `json:"resource_policies"`
	SCPCoverage       awspolicy.Coverage `json:"scp_coverage"`
	SCP               []PolicySet        `json:"scp,omitempty"`
	RCPCoverage       awspolicy.Coverage `json:"rcp_coverage"`
	RCP               []PolicySet        `json:"rcp,omitempty"`
}
type Check struct {
	PrincipalARN      string            `json:"principal_arn"`
	Action            string            `json:"action"`
	Resource          string            `json:"resource"`
	ResourceAccountID string            `json:"resource_account_id"`
	Context           awspolicy.Context `json:"context"`
}
type ActivityScope struct {
	PrincipalARN string `json:"principal_arn"`
	Action       string `json:"action"`
	Resource     string `json:"resource"`
	Complete     bool   `json:"complete"`
}
type Activity struct {
	PrincipalARN string    `json:"principal_arn"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource,omitempty"`
	At           time.Time `json:"at"`
}
type ActivityEvidence struct {
	SourceRef string          `json:"source_ref"`
	Start     time.Time       `json:"window_start"`
	End       time.Time       `json:"window_end"`
	Scopes    []ActivityScope `json:"scopes"`
	Events    []Activity      `json:"events"`
}
type Input struct {
	Checks       []Check          `json:"checks"`
	Supplemental []Supplemental   `json:"recorded_policy_evidence,omitempty"`
	Activity     ActivityEvidence `json:"recorded_activity_evidence"`
}
type Evaluation struct {
	Check               Check              `json:"check"`
	Result              awspolicy.Result   `json:"result"`
	PolicySource        string             `json:"policy_source"`
	ActivitySource      string             `json:"activity_source,omitempty"`
	ActivityCoverage    awspolicy.Coverage `json:"activity_coverage"`
	ResourceUnboundUses int                `json:"resource_unbound_uses"`
	ObservedUses        int                `json:"observed_uses"`
	Unused              bool               `json:"unused_in_covered_window"`
}
type KeyFinding struct {
	Key        awsiam.Key `json:"key"`
	AgeDays    int        `json:"age_days"`
	UnusedDays int        `json:"unused_days"`
	LongLived  bool       `json:"long_lived"`
	Stale      bool       `json:"stale"`
}
type Escalation struct {
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	Reason     string `json:"reason"`
	Confidence string `json:"confidence"`
}
type Assessment struct {
	CapturedInput Input           `json:"captured_input"`
	InputSHA256   string          `json:"input_sha256"`
	Version       int             `json:"version"`
	Provider      string          `json:"provider"`
	CollectedAt   time.Time       `json:"collected_at"`
	Identity      awsiam.Identity `json:"identity"`
	Evaluations   []Evaluation    `json:"evaluations"`
	Keys          []KeyFinding    `json:"keys"`
	Escalation    []Escalation    `json:"self_escalation_candidates"`
	ActivityStart time.Time       `json:"activity_window_start,omitempty"`
	ActivityEnd   time.Time       `json:"activity_window_end,omitempty"`
	RiskScore     int             `json:"risk_score"`
	Limitations   []string        `json:"limitations"`
}
