// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/projections"
)

// Constrained edge sub-CA commands (epic B6). Each is an event append plus
// same-transaction projection (AN-2/AN-6); the read models in
// internal/store/edge_delegation.go are rebuilt from these events alone.

// SetEdgeSegmentPolicy records a segment's opt-in (or opt-out) to delegated
// edge CAs, with the attestation roots and identifier scope that opt-in means.
func (o *Orchestrator) SetEdgeSegmentPolicy(ctx context.Context, tenantID string, in projections.EdgeSegmentPolicySet) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEdgeSegmentPolicySet, tenantID, payload)
	return err
}

// RecordEdgeDelegationIssued records a delegated CA the isolated signer minted.
func (o *Orchestrator) RecordEdgeDelegationIssued(ctx context.Context, tenantID string, in projections.EdgeDelegationIssued) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEdgeDelegationIssued, tenantID, payload)
	return err
}

// RevokeEdgeDelegation records the brain revoking a delegation. The projector
// also revokes the delegated CA's serial in the parent CA's issued ledger, so
// OCSP and the CRL carry the revocation with no new machinery.
func (o *Orchestrator) RevokeEdgeDelegation(ctx context.Context, tenantID string, in projections.EdgeDelegationRevoked) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEdgeDelegationRevoked, tenantID, payload)
	return err
}

// RecordEdgeIssuanceReconciled records one locally-issued leaf reported back
// by an edge host, verdict included.
func (o *Orchestrator) RecordEdgeIssuanceReconciled(ctx context.Context, tenantID string, in projections.EdgeIssuanceReconciled) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventEdgeIssuanceReconciled, tenantID, payload)
	return err
}
