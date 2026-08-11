// SPDX-License-Identifier: MPL-2.0

package server

import (
	"errors"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

// buildManagedKeyService asks the licensed EE factory to assemble the served
// managed-key lifecycle. Core passes only the event spine, idempotency recorder,
// and the same transactional approval/outbox checker used by issuance.
func buildManagedKeyService(d Deps, idem *orchestrator.Idempotency, outbox approvalOutbox, orch *orchestrator.Orchestrator) (api.ManagedKeyService, error) {
	if d.ManagedKeyFactory == nil {
		return nil, nil
	}
	// Managed-key rotate, revoke, and zeroize are always dual-control actions.
	// They must not inherit the unrelated CA policy toggle: the public API and EE
	// lifecycle contract promise a distinct approver even when ordinary CA
	// issuance approval is disabled. Fail closed if the durable approval store is
	// unavailable instead of silently constructing an ungated service.
	if d.Store == nil {
		return nil, errors.New("server: managed-key dual control requires the approval store")
	}
	if outbox == nil {
		return nil, errors.New("server: managed-key dual control requires the transactional notification outbox")
	}
	if orch == nil {
		return nil, errors.New("server: managed-key dual control requires the event-sourced orchestrator")
	}
	required := d.RequiredApprovals
	if required < defaultRequiredApprovals {
		required = defaultRequiredApprovals
	}
	checker := storeApprovalChecker{store: d.Store, orch: orch, required: required}
	return d.ManagedKeyFactory(ManagedKeyServiceDeps{
		Store:           d.Store,
		Log:             d.Log,
		Idempotency:     idem,
		ApprovalChecker: checker,
	})
}
