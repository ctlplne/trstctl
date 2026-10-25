// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/store"
)

// ErrIssuanceProfileRefused marks an issuance the effective certificate
// profile refuses. At a first issuance it is raised before anything is
// recorded; for work already queued it is a definite no-effect refusal at the
// mint, before any signature.
var ErrIssuanceProfileRefused = errors.New("the certificate profile refuses this issuance")

// IssuanceProfileRefused wraps the profile's own reason.
func IssuanceProfileRefused(reason error) error {
	return fmt.Errorf("%w: %w", ErrIssuanceProfileRefused, reason)
}

// IssuanceAdmissionGuard decides, before a first issuance is recorded,
// whether the certificate profile the mint will apply admits it, using only
// the checks that need no key: the enrollment protocol and the validity. The
// composition root supplies it, because only the server knows which profile
// the mint resolves. binding is the issuance binding the mint will use, or nil.
type IssuanceAdmissionGuard func(ctx context.Context, tenantID string, identity store.Identity, binding *store.OperationApprovalIssuanceBinding) error

// WithIssuanceAdmissionGuard refuses a requested -> issued transition the
// guard rejects, before any event or outbox intent. Without it a refused
// issuance was accepted, then failed at the mint on every retry.
func WithIssuanceAdmissionGuard(guard IssuanceAdmissionGuard) OrchestratorOption {
	return func(o *Orchestrator) {
		o.issuanceAdmissionGuard = guard
	}
}

// IssuanceAdmissionRefusal runs the first-issuance admission check without
// recording anything, so a preview can say what execution would refuse.
func (o *Orchestrator) IssuanceAdmissionRefusal(ctx context.Context, tenantID string, identity store.Identity, binding *store.OperationApprovalIssuanceBinding) error {
	if o == nil || o.issuanceAdmissionGuard == nil || State(identity.Status) != StateRequested {
		return nil
	}
	return o.issuanceAdmissionGuard(ctx, tenantID, identity, binding)
}
