// SPDX-License-Identifier: MPL-2.0

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
)

// ValidTriageStatus reports whether s is one of the supported triage states.
func ValidTriageStatus(s TriageStatus) bool {
	switch s {
	case TriageUnmanaged, TriageInvestigating, TriageManaged, TriageDismissed:
		return true
	default:
		return false
	}
}

// ValidateTriageTransition rejects state changes that would make triage history
// incoherent. Terminal outcomes are idempotent but not reversible.
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
		if to == TriageManaged || to == TriageDismissed {
			return nil
		}
	}
	return fmt.Errorf("%w: %q -> %q", ErrInvalidTriageTransition, from, to)
}
