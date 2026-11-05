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
	At         time.Time                  `json:"at"`
	ExpiresAt  time.Time                  `json:"expires_at"`
}
