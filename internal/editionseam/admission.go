// SPDX-License-Identifier: BUSL-1.1

package editionseam

import "context"

// AdmissionHook is a feature-neutral policy seam for deciding whether an
// issuance-side operation may proceed. Core owns only this generic contract; any
// edition-specific policy that plugs in must live behind the tagged attach seam.
type AdmissionHook interface {
	Admit(context.Context, AdmissionRequest) (AdmissionDecision, error)
}

// AdmissionRequest describes the public metadata an admission policy may inspect
// before core performs an issuance-side side effect. Inputs name the observed
// state an operation relies on, so a policy can deny only the affected operations
// instead of freezing the whole tenant.
type AdmissionRequest struct {
	TenantID        string
	Operation       string
	IdentityID      string
	IdempotencyKey  string
	Reason          string
	ObservedInputs  []ObservedStateInput
	ObservedSummary string
}

// ObservedStateInput identifies one observed-state dependency of an operation.
// AuthorityID is intentionally generic: core treats it as an opaque upstream or
// inventory plane label and never assigns product meaning to it.
type ObservedStateInput struct {
	AuthorityID string `json:"authority_id"`
	RecordKey   string `json:"record_key,omitempty"`
	Source      string `json:"source,omitempty"`
}

// AdmissionDecision is the policy result. Allowed=false refuses the operation
// before the side effect is attempted; Reason is safe public metadata.
type AdmissionDecision struct {
	Allowed   bool
	Reason    string
	RefusalID string
}

func AllowAdmission() AdmissionDecision {
	return AdmissionDecision{Allowed: true}
}
