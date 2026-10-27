// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// refuseCompromisedCSRKey refuses a CSR whose key the tenant has recorded as
// compromised, before any authority is asked to sign it (owner decision,
// batch 11; CA/B BR 6.1.1.3, condition 4). The structural weak-key checks run
// inside the signing functions themselves.
func refuseCompromisedCSRKey(ctx context.Context, st *store.Store, tenantID string, csrDER []byte) error {
	if st == nil {
		return nil
	}
	inspected, err := crypto.InspectOpaqueCSR(csrDER)
	if err != nil {
		return fmt.Errorf("server: CSR does not parse: %w", err)
	}
	return orchestrator.RefuseCompromisedSubjectKeyIn(ctx, st, tenantID, inspected.RawSubjectPublicKeyInfo)
}

// refuseCompromisedLeafKey is the same refusal on a CA authority's leaf route:
// a CSR that does not parse, or whose key the tenant recorded as compromised,
// is a request the authority refuses, answered as an invalid request that
// names why.
func refuseCompromisedLeafKey(ctx context.Context, st *store.Store, tenantID string, csrDER []byte) error {
	inspected, err := crypto.InspectOpaqueCSR(csrDER)
	if err != nil {
		return fmt.Errorf("%w: the CSR does not parse: %v", api.ErrCAHierarchyInvalid, err)
	}
	if err := refuseCompromisedPublicKey(ctx, st, tenantID, inspected.RawSubjectPublicKeyInfo); err != nil {
		if crypto.RefusedSubjectKey(err) {
			return fmt.Errorf("%w: %s", api.ErrCAHierarchyInvalid, crypto.SubjectKeyRefusalDetail(err))
		}
		return err
	}
	return nil
}

// refuseCompromisedPublicKey is the same refusal for a bare public key (an
// SVID's, an agent's).
func refuseCompromisedPublicKey(ctx context.Context, st *store.Store, tenantID string, spkiDER []byte) error {
	return orchestrator.RefuseCompromisedSubjectKeyIn(ctx, st, tenantID, spkiDER)
}

// agentKeyGuard refuses an agent key the tenant recorded as compromised, at
// bootstrap and renewal.
func agentKeyGuard(st *store.Store) func(context.Context, string, []byte) error {
	return func(ctx context.Context, tenantID string, spkiDER []byte) error {
		return refuseCompromisedPublicKey(ctx, st, tenantID, spkiDER)
	}
}
