// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// retainedIdentityProfile resolves the policy selected by the first accepted
// issuance when no explicit profile attribute exists. One indexed lookup and
// one exact event read avoid scanning the log
// on every renewal. Explicit identity attributes still take precedence.
func (o *Orchestrator) retainedIdentityProfile(ctx context.Context, tenantID, identityID string) (string, error) {
	initial, found, err := o.store.IdentityInitialIssuance(ctx, tenantID, identityID)
	if err != nil || !found {
		return "", err
	}
	if o.log == nil {
		return "", fmt.Errorf("orchestrator: identity issuance policy event log is unavailable")
	}
	event, found, err := o.log.EventAtSequence(ctx, initial.Seq)
	if err != nil {
		return "", fmt.Errorf("orchestrator: read identity issuance policy evidence: %w", err)
	}
	if !found || event.Sequence != initial.Seq || event.TenantID != tenantID || event.Type != projections.EventIdentityIssued {
		return "", fmt.Errorf("orchestrator: identity %s issuance policy evidence is missing or does not match its tenant", identityID)
	}
	if err := projections.ValidateLifecycleApprovalEvent(event); err != nil {
		return "", fmt.Errorf("orchestrator: invalid identity issuance policy evidence: %w", err)
	}
	var payload transitionPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return "", fmt.Errorf("orchestrator: decode identity issuance policy evidence: %w", err)
	}
	if payload.IdentityID != identityID || payload.From != StateRequested || payload.To != StateIssued || payload.IdempotencyKey != initial.IdempotencyKey {
		return "", fmt.Errorf("orchestrator: identity %s issuance policy evidence names a different command", identityID)
	}
	var binding *store.OperationApprovalIssuanceBinding
	switch event.SchemaVersion {
	case projections.LifecycleIssuanceEventSchemaVersion:
		binding = payload.Issuance
	case projections.LifecycleApprovalEventSchemaVersion:
		binding = payload.Approval.Issuance
	default:
		// Historical transitions predate reviewed profile bindings. They cannot
		// gain policy authority by carrying a field their schema did not define.
		if payload.Issuance != nil || payload.Approval != nil || event.SchemaVersion > projections.LifecycleSideEffectEventSchemaVersion {
			return "", fmt.Errorf("orchestrator: unsupported identity issuance policy evidence schema")
		}
		return "", nil
	}
	if binding == nil || strings.TrimSpace(binding.ProfileName) == "" {
		return "", nil
	}
	if _, err := binding.EvidenceRefs(); err != nil {
		return "", fmt.Errorf("orchestrator: incomplete identity issuance policy evidence: %w", err)
	}
	original, err := o.store.GetProfileVersion(ctx, tenantID, binding.ProfileName, binding.ProfileVersion)
	if err != nil {
		return "", fmt.Errorf("orchestrator: resolve identity's original certificate policy: %w", err)
	}
	if original.ID != binding.ProfileID || store.ProfileSpecDigest(original.Spec) != binding.ProfileSpecDigest {
		return "", fmt.Errorf("orchestrator: identity's original certificate policy evidence drifted")
	}
	// Follow this policy's active revision for the next command. The original
	// approval is evidence of selection, not authority to spend it again.
	return binding.ProfileName, nil
}
