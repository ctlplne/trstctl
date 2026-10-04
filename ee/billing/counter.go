// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/usage"

	corestore "trstctl.com/trstctl/internal/store"
)

// StoreTenantCounter counts a tenant's current stock of quota-limited
// resources from the read model (epic L2).
//
// The counter answers "how many does this tenant HAVE", which is what a
// stored-resource cap compares against — not the meters, which answer "how
// many did this tenant DO". Counting certificates by meter would let a tenant
// whose old certificates expired stay over a cap they are actually under.
//
// Missing resources are absent from the map and are counted as zero. A missing
// datastore or tenant, however, is an authority outage: admitting creation
// without a count would let a Provider cap be bypassed.
func StoreTenantCounter(s *corestore.Store) TenantCounter {
	return func(ctx context.Context, tenantID string) (TenantCounts, error) {
		if s == nil || tenantID == "" {
			return nil, errors.New("billing: tenant resource counter is unavailable")
		}
		out := TenantCounts{}
		err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var err error
			out, err = countTenantResources(ctx, tx, tenantID)
			return err
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	}
}

// The durable collector uses the same queries inside its observation transaction.
func countTenantResources(ctx context.Context, tx pgx.Tx, tenantID string) (TenantCounts, error) {
	out := TenantCounts{}
	for resource, query := range map[string]string{
		usage.MeterAgents: `SELECT count(*) FROM agents
				  WHERE tenant_id = $1 AND status <> 'offboarded'`,
		usage.MeterCertificatesStored: `SELECT count(*) FROM certificates
				  WHERE tenant_id = $1 AND status <> 'revoked'`,
		usage.MeterSecretsStored: `SELECT count(*) FROM credentials
				  WHERE tenant_id = $1`,
	} {
		var n int64
		if err := tx.QueryRow(ctx, query, tenantID).Scan(&n); err != nil {
			return nil, err
		}
		out[resource] = n
	}
	return out, nil
}
