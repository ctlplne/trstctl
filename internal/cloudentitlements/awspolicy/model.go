// SPDX-License-Identifier: BUSL-1.1

// Package awspolicy evaluates bounded AWS permission evidence for one request.
// It is advisory: an unread policy or unsupported rule cannot justify an Allow.
package awspolicy

import "encoding/json"

type Coverage string

const (
	Complete    Coverage = "complete"
	Absent      Coverage = "verified_absent"
	Unavailable Coverage = "unavailable"
)

type Decision string

const (
	Allowed       Decision = "allowed"
	ExplicitDeny  Decision = "explicit_deny"
	ImplicitDeny  Decision = "implicit_deny"
	Indeterminate Decision = "indeterminate"
)

type PrincipalKind string

const (
	IAMUser          PrincipalKind = "iam_user"
	IAMRole          PrincipalKind = "iam_role"
	RoleSession      PrincipalKind = "role_session"
	FederatedSession PrincipalKind = "federated_session"
)

// Principal records the calling identity. RoleARN identifies a role session's
// issuer; AccountID and ResourceAccountID make cross-account scope explicit.
type Principal struct {
	Kind      PrincipalKind `json:"kind"`
	ARN       string        `json:"arn"`
	RoleARN   string        `json:"role_arn,omitempty"`
	AccountID string        `json:"account_id"`
}

// Context distinguishes a missing AWS key from missing evidence about that key.
// Complete is true only for a fully known request context, never a partial log.
type Context struct {
	Values     map[string][]string `json:"values,omitempty"`
	AbsentKeys []string            `json:"absent_keys,omitempty"`
	Complete   bool                `json:"complete"`
}
type Request struct {
	Principal         Principal `json:"principal"`
	Action            string    `json:"action"`
	Resource          string    `json:"resource"`
	ResourceAccountID string    `json:"resource_account_id"`
	Context           Context   `json:"context"`
}

// PolicySet is a policy category or one Organizations hierarchy level. Policies
// at a level combine; all applicable hierarchy levels must permit the request.
type PolicySet struct {
	Coverage  Coverage
	Documents []Document
}
type Evidence struct {
	Identity    PolicySet
	Resource    PolicySet
	Boundary    PolicySet
	Session     PolicySet
	SCP         []PolicySet
	RCP         []PolicySet
	SCPCoverage Coverage
	RCPCoverage Coverage
}
type Reason struct {
	Source    string `json:"source"`
	Statement string `json:"statement,omitempty"`
	Detail    string `json:"detail"`
}
type Result struct {
	Decision Decision `json:"decision"`
	Reasons  []Reason `json:"reasons"`
}

// Document can only be constructed through Parse, which owns the raw JSON copy.
// Its fields stay private so callers cannot mutate a reviewed rule after parsing.
type Document struct {
	id         string
	raw        json.RawMessage
	statements []statement
}

func (d Document) ID() string { return d.id }

// RawJSON returns an owned copy for a source receipt or policy diff.
func (d Document) RawJSON() []byte { return append([]byte(nil), d.raw...) }
