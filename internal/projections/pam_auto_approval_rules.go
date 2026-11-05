// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"time"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventPAMAutoApprovalRuleSaved   = "pam.auto_approval_rule.saved"
	EventPAMAutoApprovalRuleDeleted = "pam.auto_approval_rule.deleted"
	EventPAMAutoApprovalApplied     = "pam.auto_approval.applied"
)

// PAMAutoApprovalRuleSaved is the complete policy revision. The store's
// value has stable snake-case JSON names and contains no credential material.
type PAMAutoApprovalRuleSaved struct {
	Rule store.PAMAutoApprovalRule `json:"rule"`
}

type PAMAutoApprovalRuleDeleted struct {
	ID       string    `json:"id"`
	Revision int64     `json:"revision"`
	Actor    string    `json:"actor"`
	At       time.Time `json:"at"`
}

// PAMAutoApprovalApplied names the exact rule decision. Matched values are
// request metadata, never a credential, attestation payload or bind parameter.
type PAMAutoApprovalApplied struct {
	RuleID            string    `json:"rule_id"`
	RuleName          string    `json:"rule_name"`
	RuleRevision      int64     `json:"rule_revision"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Kind              string    `json:"kind"`
	TargetType        string    `json:"target_type"`
	TargetID          string    `json:"target_id"`
	Folder            string    `json:"folder,omitempty"`
	Requester         string    `json:"requester"`
	MatchedRoles      []string  `json:"matched_roles,omitempty"`
	Window            string    `json:"window,omitempty"`
	Ticket            string    `json:"ticket,omitempty"`
	At                time.Time `json:"at"`
}
