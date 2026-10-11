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

func (h *caHierarchyService) GetCrossSignReceipt(ctx context.Context, tenantID, ceremonyID string) (api.CACrossSign, error) {
	rec, err := h.store.GetCACrossSignReceipt(ctx, tenantID, ceremonyID)
	if store.IsNotFound(err) {
		// Older checkpoints consumed ca.cross_signed before this indexed read
		// model existed. Recover one exact immutable event by its deterministic
		// ID, then project it normally. Never scan the tenant or global log on a
		// request path, and never project another tenant's event.
		for _, eventID := range []string{"ca-cross-sign-" + ceremonyID, "ca-offline-cross-sign-" + ceremonyID} {
			event, found, lookupErr := h.log.EventByID(ctx, eventID)
			if lookupErr != nil {
				return api.CACrossSign{}, lookupErr
			}
			if !found || event.TenantID != tenantID || event.Type != projections.EventCACrossSigned {
				continue
			}
			var payload caCrossSignedEvent
			if json.Unmarshal(event.Data, &payload) != nil || payload.CeremonyID != ceremonyID {
				return api.CACrossSign{}, fmt.Errorf("%w: cross-sign event identity mismatch", api.ErrCAHierarchyConflict)
			}
			if projectErr := h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return projections.New(h.store).ApplyTx(ctx, tx, event)
			}); projectErr != nil {
				return api.CACrossSign{}, projectErr
			}
			rec, err = h.store.GetCACrossSignReceipt(ctx, tenantID, ceremonyID)
			break
		}
	}
	if err != nil {
		return api.CACrossSign{}, err
	}
	return api.CACrossSign{
		IssuerAuthorityID: rec.IssuerAuthorityID, TargetSHA256: rec.TargetSHA256,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rec.CrossCertificateDER})),
		CeremonyID:     rec.CeremonyID, Imported: rec.Imported,
	}, nil
}
