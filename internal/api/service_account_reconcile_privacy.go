// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"encoding/hex"
	"strings"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This check follows validation of the immutable schema-two root and its exact
// effect digest. It reads authority ALREADY consumed by that root; it cannot
// approve, consume, enqueue or revive a grant. Erasure deliberately replaces SQL
// approval coordinates with a closed marker after preserving the canonical root.
// New queue admission always uses ValidateOperationApprovalUseTx unchanged.
func validateConsumedReconcileReadAuthority(rootID, accountName string, use store.OperationApprovalUse, r store.OperationApprovalRequest) error {
	if r.ID != use.RequestID || r.IntentDigest != use.IntentDigest || r.Status != store.ApprovalStatusConsumed || r.ConsumedEventID != rootID || use.ResourceKind != projections.ServiceReconcileApprovalKind || use.ResourceID != rootID || use.Action != "reconcile" {
		return store.ErrApprovalDrifted
	}
	if err := store.ValidateOperationApprovalUseBinding(r, use); err == nil {
		return nil
	}
	if r.TargetVersion != use.TargetVersion || r.RequiredApprovals != use.RequiredApprovals || r.Reason != "" || len(r.EvidenceRefs) != 0 {
		return store.ErrApprovalDrifted
	}
	marker := r.Requester
	if privacy.IsPlaceholder(marker) && use.Requester == marker && r.ResourceKind == marker && r.ResourceID == marker && r.ResourceName == marker && r.Action == marker && r.FromState == marker && r.ToState == marker {
		return nil
	}
	// Retention keeps immutable source history. Only the closed, spent row may
	// omit reviewer identity/text; every retained effect coordinate must still match.
	suffix, retained := strings.CutPrefix(marker, "retained:")
	raw, err := hex.DecodeString(suffix)
	if retained && err == nil && len(raw) == 6 && suffix == strings.ToLower(suffix) && r.ResourceKind == use.ResourceKind && r.ResourceID == use.ResourceID && r.ResourceName == accountName && r.Action == use.Action && r.FromState == use.FromState && r.ToState == use.ToState {
		return nil
	}
	return store.ErrApprovalDrifted
}
