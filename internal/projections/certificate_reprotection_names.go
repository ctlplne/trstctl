// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// backfillCertificateReprotectionIssuerNames repairs a derived identity label
// left stale by older projectors. It reads only cutover events from the durable
// type index and advances a separate cursor after the whole finite pass. The
// ordinary projection checkpoint cannot attest this newer field.
func (p *Projector) backfillCertificateReprotectionIssuerNames(ctx context.Context, log *events.Log, through uint64) error {
	checked, err := p.store.CAReprotectionNameRecoveryCursor(ctx)
	if err != nil {
		return err
	}
	if checked > through {
		return fmt.Errorf("projections: CA re-protection name cursor %d exceeds head %d", checked, through)
	}
	if checked == through {
		return nil
	}
	err = log.ReplayTypesThrough(ctx, checked+1, through, []string{EventCertificateReprotectionCutover}, func(e events.Event) error {
		var cut store.CertificateReprotectionCutover
		if err := json.Unmarshal(e.Data, &cut); err != nil {
			return fmt.Errorf("projections: decode CA re-protection cutover for name recovery: %w", err)
		}
		if err := store.ValidateCertificateReprotectionCutover(e.TenantID, cut); err != nil {
			return err
		}
		// Tenant offboarding removes this read model. Replaying retained history
		// must not recreate a display label for a removed tenant.
		if _, err := p.store.GetTenant(ctx, e.TenantID); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		return p.store.WithTenantProjection(ctx, e.TenantID, func(tx pgx.Tx) error {
			return p.store.RepairCertificateReprotectionIssuerNameTx(ctx, tx, e.TenantID, cut)
		})
	})
	if err != nil {
		return err
	}
	return p.store.MarkCAReprotectionNameCheckedThrough(ctx, through)
}
