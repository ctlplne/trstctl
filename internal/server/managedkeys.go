package server

import (
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

// buildManagedKeyService asks the licensed EE factory to assemble the served
// managed-key lifecycle. Core passes only the event spine, idempotency recorder,
// and the same dual-control checker used by issuance.
func buildManagedKeyService(d Deps, idem *orchestrator.Idempotency) (api.ManagedKeyService, error) {
	if d.ManagedKeyFactory == nil {
		return nil, nil
	}
	var checker api.ApprovalChecker
	if d.RequireApproval && d.Store != nil {
		required := d.RequiredApprovals
		if required <= 0 {
			required = defaultRequiredApprovals
		}
		checker = storeApprovalChecker{store: d.Store, required: required}
	}
	return d.ManagedKeyFactory(ManagedKeyServiceDeps{
		Log:             d.Log,
		Idempotency:     idem,
		ApprovalChecker: checker,
	})
}
