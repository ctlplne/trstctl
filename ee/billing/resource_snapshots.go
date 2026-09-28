// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/usage"
)

type resourceObservation struct {
	registration string
	at           time.Time
}

// collectResources reads and publishes one customer's gauges under the same
// privacy -> projection -> live-registration fence as issuance reconciliation.
// A stale replica cannot publish an older read after a newer snapshot, and an
// erased/replaced registration cannot inherit its predecessor's observation.
func (p *PGStore) collectResources(ctx context.Context, tenantID string, previous resourceObservation, now func() time.Time, maxGap time.Duration) (resourceObservation, error) {
	var next resourceObservation
	err := p.store.WithPrivacyReadModelReplacementBarrier(ctx, func(ctx context.Context) error {
		return p.store.WithProjectionLock(ctx, func(ctx context.Context) error {
			return p.tx(ctx, tenantID, func(tx pgx.Tx) error {
				registration, err := p.observationRegistrationTx(ctx, tx, tenantID)
				if err != nil {
					return err
				}
				counts, err := countTenantResources(ctx, tx, tenantID)
				if err != nil {
					return err
				}
				next = resourceObservation{registration: registration, at: now().UTC()}
				// This row is this customer's presence, never a count of neighbors.
				counts[usage.MeterTenants] = 1
				for meter, value := range counts {
					if _, err := tx.Exec(ctx, `INSERT INTO provider_usage_meters
						(tenant_id,meter,period_start,kind,value)
						VALUES ($1,$2,$3,'gauge',$4)
						ON CONFLICT (tenant_id,meter,period_start) DO UPDATE
						SET kind='gauge',value=EXCLUDED.value,updated_at=now()`,
						tenantID, meter, PeriodStart(next.at), value); err != nil {
						return err
					}
				}
				// A new process, failed sweep, missed heartbeat, clock reversal or
				// changed registration starts a new observation, never a bridge.
				if previous.registration != registration || previous.at.IsZero() ||
					!next.at.After(previous.at) || next.at.Sub(previous.at) > maxGap {
					return nil
				}
				_, err = tx.Exec(ctx, `INSERT INTO provider_usage_coverage
					(tenant_id,observed_from,observed_to,observed_ranges)
					VALUES ($1,$2,$3,tstzmultirange(tstzrange($2,$3,'[)')))
					ON CONFLICT (tenant_id) DO UPDATE SET
					observed_from=LEAST(provider_usage_coverage.observed_from,EXCLUDED.observed_from),
					observed_to=GREATEST(provider_usage_coverage.observed_to,EXCLUDED.observed_to),
					observed_ranges=COALESCE(provider_usage_coverage.observed_ranges,'{}'::tstzmultirange)+EXCLUDED.observed_ranges,
					updated_at=now()`, tenantID, previous.at, next.at)
				return err
			})
		})
	})
	return next, err
}

func (p *PGStore) resourceTenants(ctx context.Context) ([]string, error) {
	tenants, err := p.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		ids = append(ids, tenant.TenantID)
	}
	return ids, nil
}
