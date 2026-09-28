// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

var ErrIssuanceHistoryUnknown = errors.New("billing: issuance history is not verified")

// RefreshIssuedCounters materializes hourly totals from committed mint facts.
// It does not depend on a serving process surviving long enough to flush a hint.
// Each customer commits separately, and repeated or concurrent refreshes replace
// totals rather than incrementing them again. Recovery proves counts, not uptime:
// this path must never widen observation coverage.
func (p *PGStore) RefreshIssuedCounters(ctx context.Context) error {
	if p == nil || p.store == nil {
		return errors.New("billing: durable issuance store is unavailable")
	}
	// One serial sweep cannot outlive the next minute tick or accumulate workers.
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	tenants, err := p.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, tenant := range tenants {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		tenantCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		err := p.refreshIssuedTenant(tenantCtx, tenant.TenantID)
		stop()
		if err != nil {
			failures = append(failures, fmt.Errorf("billing: refresh issuance for %s: %w", tenant.TenantID, err))
		}
	}
	return errors.Join(failures...)
}

func (p *PGStore) refreshIssuedTenant(ctx context.Context, tenantID string) error {
	// Keep the established privacy -> projection -> tenant-lifecycle order.
	// The projection lock prevents a snapshot/rebuild from taking table locks
	// ahead of our lifecycle lock. Other replicas use the same lock, so a stale
	// refresh cannot overwrite a newer refresh. Live minting remains independent.
	return p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(ctx context.Context) error {
		return p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
			return p.tx(ctx, tenantID, func(tx pgx.Tx) error {
				if _, err := p.store.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID); err != nil {
					if errors.Is(err, corestore.ErrApplicationSecretTenantEpochMismatch) {
						// The customer disappeared after registry enumeration. No
						// data was carried from that enumeration into this transaction.
						return nil
					}
					return err
				}
				var unknown bool
				if err := tx.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM tenants WHERE tenant_id=$1 AND responder_issuance_history_known IS TRUE)
					OR EXISTS (
					SELECT 1 FROM certificate_metadata_receipts
					WHERE tenant_id=$1 AND (issuance_status IS NULL OR issuance_status='unverifiable')
				) OR EXISTS (SELECT 1 FROM ca_issued_certs c WHERE c.tenant_id=$1
					AND (c.issuance_event_id IS NULL OR
						(c.issuance_event_type <> 'edge.delegation.issued' AND NOT EXISTS (
							SELECT 1 FROM certificate_metadata_receipts r
							WHERE r.tenant_id=$1 AND r.event_id=c.issuance_event_id))))`, tenantID).Scan(&unknown); err != nil {
					return err
				}
				if unknown {
					return ErrIssuanceHistoryUnknown
				}
				if _, err := tx.Exec(ctx, `DELETE FROM provider_usage_meters
					WHERE tenant_id=$1 AND meter=$2`, tenantID, usage.MeterCertificatesIssued); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `INSERT INTO provider_usage_meters
					(tenant_id,meter,period_start,kind,value)
					SELECT $1,$2,date_trunc('hour',minted_at,'UTC'),'counter',count(*)
					FROM (
						SELECT DISTINCT ON (issuance_fingerprint) issuance_time AS minted_at
						FROM certificate_metadata_receipts
						WHERE tenant_id=$1 AND issuance_status='mint'
						ORDER BY issuance_fingerprint,event_sequence
					) mints
					GROUP BY date_trunc('hour',minted_at,'UTC')
					ON CONFLICT (tenant_id,meter,period_start)
					DO UPDATE SET value=EXCLUDED.value,kind='counter',updated_at=now()`,
					tenantID, usage.MeterCertificatesIssued)
				return err
			})
		})
	})
}
