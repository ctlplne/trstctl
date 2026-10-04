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
	return storeTenantCounter(s, false)
}

// StoreTenantAdmissionCounter includes durable first-create commands that have
// claimed a secret name but have not yet committed their sealed row. Those
// commands reserve capacity across process crashes and replica handoff. Signed
// usage evidence must continue to call StoreTenantCounter: a pending command
// is not a stored secret and must not inflate the observed stock gauge.
func StoreTenantAdmissionCounter(s *corestore.Store) TenantCounter {
	return storeTenantCounter(s, true)
}

func storeTenantCounter(s *corestore.Store, includePending bool) TenantCounter {
	return func(ctx context.Context, tenantID string) (TenantCounts, error) {
		if s == nil || tenantID == "" {
			return nil, errors.New("billing: tenant resource counter is unavailable")
		}
		out := TenantCounts{}
		err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			var err error
			out, err = countTenantResources(ctx, tx, tenantID)
			if err != nil || !includePending {
				return err
			}
			var reserved int64
			if err := tx.QueryRow(ctx, `SELECT count(*)
				FROM application_secret_mutation_fences AS f
				LEFT JOIN operation_approval_requests AS approval
				  ON approval.tenant_id = f.tenant_id
				 AND approval.id::text = f.approval->>'request_id'
				WHERE f.tenant_id = $1 AND f.event_type = 'secret.created'
				  AND NOT EXISTS (
				    SELECT 1 FROM secret_store AS materialized
				     WHERE materialized.tenant_id = f.tenant_id
				       AND materialized.name = f.secret_name)
				  AND (f.event_time IS NOT NULL OR f.approval IS NULL OR approval.id IS NULL
				       OR (approval.status IN ('pending', 'approved') AND approval.expires_at > now()))`,
				tenantID).Scan(&reserved); err != nil {
				return err
			}
			out[usage.MeterSecretsStored] += reserved
			return nil
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
		usage.MeterSecretsStored: `SELECT
				  (SELECT count(*) FROM credentials WHERE tenant_id = $1) +
				  (SELECT count(*) FROM secret_store WHERE tenant_id = $1)`,
	} {
		var n int64
		if err := tx.QueryRow(ctx, query, tenantID).Scan(&n); err != nil {
			return nil, err
		}
		out[resource] = n
	}
	return out, nil
}
