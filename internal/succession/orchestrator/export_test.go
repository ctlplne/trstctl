// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"

	"trstctl.com/trstctl/internal/succession"
)

// RewrapDataKeysForTest drives the data half of a KEM re-wrap directly, so a
// test can prove the per-target receipts and the stage completion without the
// paired-signing mint that needs a live signer.
func (w *BreadthWorker) RewrapDataKeysForTest(ctx context.Context, tenantID, identityID string, predecessorEpoch uint64, stages []string, requestID string, requestDigest []byte, inventorySequence uint64, emptyAttested bool) error {
	return w.rewrapDataKeys(ctx, tenantID, kemRewrapPayload{
		IdentityID: identityID, PredecessorEpoch: predecessorEpoch,
		SuccessorKEMHandle: succession.TenantKEMKeyHandle(tenantID, identityID, predecessorEpoch+1), Stages: stages,
		InventorySequence: inventorySequence, EmptyInventoryAttested: emptyAttested,
	}, requestID, requestDigest)
}
