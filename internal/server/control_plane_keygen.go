// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24 (A120/A130/A132): a per-tenant switch over
// control-plane key generation. Identity issuance without a CSR, and the
// renewal of an identity whose key the control plane generated, consult it.

// controlPlaneKeygenAllowed reads the tenant's decision. A tenant with none
// predates the switch and keeps the behavior it had: allowed.
func controlPlaneKeygenAllowed(ctx context.Context, st *store.Store, tenantID string) (bool, error) {
	if st == nil {
		return true, nil
	}
	policy, found, err := st.ControlPlaneKeygenFor(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return !found || policy.Enabled, nil
}

// controlPlaneKeygenGuard is the orchestrator's first-issuance check: a
// requested -> issued transition with no CSR, for an identity whose target
// does not execute on a host agent, would have the control plane generate the
// subject key, which a tenant with the switch off refuses before anything is
// recorded.
func controlPlaneKeygenGuard(st *store.Store) orchestrator.ControlPlaneKeygenGuard {
	return func(ctx context.Context, tenantID string, ident store.Identity, subjectCSRPEM string) error {
		if strings.TrimSpace(subjectCSRPEM) != "" || subjectCSRFromIdentity(ident) != "" {
			return nil
		}
		allowed, err := controlPlaneKeygenAllowed(ctx, st, tenantID)
		if err != nil || allowed {
			return err
		}
		if _, hostExecuted, err := hostExecutedTarget(ctx, st, tenantID, ident); err != nil || hostExecuted {
			return err
		}
		return orchestrator.ErrControlPlaneKeygenOff
	}
}

// requireControlPlaneKeygen is the mint-time check for work queued before the
// tenant turned the switch off. Nothing was generated yet, so the refusal is
// a definite no-effect: the job retries and completes if the tenant turns key
// generation back on, and otherwise fails naming the switch.
func (d *issuanceDispatcher) requireControlPlaneKeygen(ctx context.Context, tenantID string) error {
	allowed, err := controlPlaneKeygenAllowed(ctx, d.store, tenantID)
	if err != nil {
		return err
	}
	if !allowed {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: %w", orchestrator.ErrControlPlaneKeygenOff))
	}
	return nil
}
