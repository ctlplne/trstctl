// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReconcileStoppedIdentityWork applies retained revocation/retirement authority
// after an executor lease expires, or after an upgrade encounters old pending
// work. It does not append a replacement command or rewrite an issuance binding.
func (p *Projector) ReconcileStoppedIdentityWork(ctx context.Context, tenantID string, now time.Time) (int64, error) {
	var stopped int64
	err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		stopped, err = p.stopIdentityWorkTx(ctx, tx, tenantID, "", now)
		return err
	})
	return stopped, err
}

func (p *Projector) stopIdentityWorkTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, now time.Time) (int64, error) {
	stops, err := p.store.TerminalIdentityWorkStopsTx(ctx, tx, tenantID, identityID, now)
	if err != nil {
		return 0, err
	}
	var count int64
	for _, stop := range stops {
		n, err := p.store.ApplyIdentityWorkStopTx(ctx, tx, tenantID, stop, now)
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}
