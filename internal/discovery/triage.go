// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"errors"
	"fmt"
)

// ErrInvalidTriageTransition marks an illegal finding triage transition.
var ErrInvalidTriageTransition = errors.New("discovery: invalid triage transition")

// TriageStatus is the operator-facing lifecycle for a discovery finding. The
// finding itself is immutable evidence; this status is a projected triage view.
type TriageStatus string

const (
	TriageUnmanaged     TriageStatus = "unmanaged"
	TriageInvestigating TriageStatus = "investigating"
	TriageManaged       TriageStatus = "managed"
	TriageDismissed     TriageStatus = "dismissed"
	// TriageRemediated records that the exposure was fixed, with evidence of
	// the fix (A106).
	TriageRemediated TriageStatus = "remediated"
	// TriageAcceptedRisk records a time-boxed acceptance; the finding reopens
	// when the acceptance expires (A106).
	TriageAcceptedRisk TriageStatus = "accepted_risk"
)

// ValidTriageStatus reports whether s is one of the supported triage states.
func ValidTriageStatus(s TriageStatus) bool {
	switch s {
	case TriageUnmanaged, TriageInvestigating, TriageManaged, TriageDismissed, TriageRemediated, TriageAcceptedRisk:
		return true
	default:
		return false
	}
}

// ValidateTriageTransition rejects state changes that would make triage history
// incoherent. Managed and dismissed are terminal: idempotent but not
// reversible. A remediation that did not hold is reopened; an accepted risk is
// reopened at expiry or when withdrawn, and may still be investigated or fixed.
func ValidateTriageTransition(from, to TriageStatus) error {
	if !ValidTriageStatus(from) {
		return fmt.Errorf("discovery: unknown current triage status %q", from)
	}
	if !ValidTriageStatus(to) {
		return fmt.Errorf("discovery: unknown target triage status %q", to)
	}
	if from == to {
		return nil
	}
	switch from {
	case TriageUnmanaged:
		return nil
	case TriageInvestigating:
		if to == TriageManaged || to == TriageDismissed || to == TriageRemediated || to == TriageAcceptedRisk {
			return nil
		}
	case TriageRemediated:
		if to == TriageUnmanaged {
			return nil
		}
	case TriageAcceptedRisk:
		if to == TriageUnmanaged || to == TriageInvestigating || to == TriageRemediated {
			return nil
		}
	}
	return fmt.Errorf("%w: %q -> %q", ErrInvalidTriageTransition, from, to)
}
