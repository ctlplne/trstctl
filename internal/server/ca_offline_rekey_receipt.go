// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// GetOfflineRootRekeyReceipt recovers a public trust-path package by its exact
// ceremony key. Old checkpoints may predate the receipt projection; one indexed
// event-ID lookup repairs that single read model without replaying the log.
func (h *caHierarchyService) GetOfflineRootRekeyReceipt(ctx context.Context, tenantID, ceremonyID string) (api.CAOfflineRootRekey, error) {
	rec, err := h.store.GetCAOfflineRekeyReceipt(ctx, tenantID, ceremonyID)
	if store.IsNotFound(err) {
		event, found, lookupErr := h.log.EventByID(ctx, "ca-offline-root-rekey-"+ceremonyID)
		if lookupErr != nil {
			return api.CAOfflineRootRekey{}, lookupErr
		}
		if found && event.TenantID == tenantID && event.Type == projections.EventCAAuthorityRekeyed {
			var payload projections.CAAuthorityRekeyed
			if json.Unmarshal(event.Data, &payload) != nil || !payload.OfflineRoot || payload.CeremonyID != ceremonyID {
				return api.CAOfflineRootRekey{}, fmt.Errorf("%w: offline-root re-key event identity mismatch", api.ErrCAHierarchyConflict)
			}
			if projectErr := h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return h.store.ApplyCAOfflineRekeyReceiptTx(ctx, tx, store.CAOfflineRekeyReceipt{
					TenantID: tenantID, CeremonyID: ceremonyID,
					PredecessorAuthorityID: payload.PredecessorCAID, SuccessorAuthorityID: payload.ID,
					NewSignedByPreviousDER: payload.NewSignedByPreviousDER,
					PreviousSignedByNewDER: payload.PreviousSignedByNewDER, CompletedAt: event.Time,
				})
			}); projectErr != nil {
				return api.CAOfflineRootRekey{}, projectErr
			}
			rec, err = h.store.GetCAOfflineRekeyReceipt(ctx, tenantID, ceremonyID)
		}
	}
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	predecessor, err := h.store.GetCAAuthority(ctx, tenantID, rec.PredecessorAuthorityID)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	successor, err := h.store.GetCAAuthority(ctx, tenantID, rec.SuccessorAuthorityID)
	if err != nil {
		return api.CAOfflineRootRekey{}, err
	}
	if successor.ReplacesID == nil || *successor.ReplacesID != predecessor.ID || successor.SignerHandle != "" {
		return api.CAOfflineRootRekey{}, fmt.Errorf("%w: offline-root receipt lineage does not match current authorities", api.ErrCAHierarchyConflict)
	}
	return api.CAOfflineRootRekey{
		CeremonyID: ceremonyID, Rotation: authorityRotationResponse(predecessor, successor),
		NewSignedByPreviousPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.NewSignedByPreviousDER})),
		PreviousSignedByNewPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.PreviousSignedByNewDER})),
	}, nil
}
