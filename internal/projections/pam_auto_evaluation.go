// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"time"
	"trstctl.com/trstctl/internal/store"
)

const EventPAMAutoApprovalEvaluated = "pam.auto_approval.evaluated"

// PAMAutoApprovalFacts is the witness to each criterion that matched. It
// contains requester metadata, never the upstream credential or proof payload.
type PAMAutoApprovalFacts struct {
	Target string   `json:"target"`
	Folder string   `json:"folder,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Window string   `json:"window,omitempty"`
	Ticket string   `json:"ticket,omitempty"`
}

// PAMAutoApprovalEvaluated freezes the first rule choice, including no-match.
// Its deterministic source identity survives a lost reply and a cold rebuild.
type PAMAutoApprovalEvaluated struct {
	RequestID  string                     `json:"request_id"`
	Kind       string                     `json:"kind"`
	Requester  string                     `json:"requester"`
	BaseDigest string                     `json:"base_digest"`
	TargetType string                     `json:"target_type"`
	TargetID   string                     `json:"target_id"`
	Folder     string                     `json:"folder,omitempty"`
	Rule       *store.PAMAutoApprovalRule `json:"rule,omitempty"`
	Facts      *PAMAutoApprovalFacts      `json:"facts,omitempty"`
	// Standing is the access bundle standing approval (OD-9) that approved
	// a run's session request when no rule did.
	Standing  *PAMStandingApprovalMatch `json:"standing,omitempty"`
	At        time.Time                 `json:"at"`
	ExpiresAt time.Time                 `json:"expires_at"`
}

// PAMStandingApprovalMatch is the standing approval of an access bundle's
// delegated account (OD-9) that approved a run's session request, frozen with
// the evaluation: the approval, its bundle, the run, the run's principal, the
// role and when the approval expires.
type PAMStandingApprovalMatch struct {
	ApprovalID string    `json:"approval_id"`
	BundleID   string    `json:"bundle_id"`
	RunID      string    `json:"run_id"`
	Principal  string    `json:"principal"`
	Role       string    `json:"role"`
	ExpiresAt  time.Time `json:"expires_at"`
}
