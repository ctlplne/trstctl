// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Wire evidence for replaced endpoints (X3-L1). A good observation that finds
// an endpoint serving another certificate than before records the replacement
// (ApplyEndpointVerificationTx); the leader's traffic pass then looks for an
// observer agent's new connections at the endpoint and records them, or, once
// the window has passed, that none came.

// maxEndpointsAwaitingTraffic bounds one tenant pass.
const maxEndpointsAwaitingTraffic = 1000

// TenantsWithEndpointsAwaitingTraffic enumerates tenants holding a replaced
// endpoint without wire evidence, so the leader's traffic pass can visit each
// tenant under its own RLS context.
func (s *Store) TenantsWithEndpointsAwaitingTraffic(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold a replaced endpoint awaiting wire evidence so the leader-only traffic pass can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM endpoint_verifications
		  WHERE replaced_at IS NOT NULL AND traffic_observed_at IS NULL AND reached AND mismatch = '' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// EndpointsAwaitingTraffic returns the tenant's replaced endpoints that still
// serve their replacement and have no wire evidence yet, oldest replacement
// first.
func (s *Store) EndpointsAwaitingTraffic(ctx context.Context, tenantID string) ([]EndpointVerification, error) {
	var out []EndpointVerification
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT endpoint_id, address, vantage, observed_fingerprint, COALESCE(replaced_fingerprint, ''), replaced_at,
			        traffic_unobserved_since
			   FROM endpoint_verifications
			  WHERE tenant_id = $1 AND replaced_at IS NOT NULL AND traffic_observed_at IS NULL AND reached AND mismatch = ''
			  ORDER BY replaced_at, endpoint_id, vantage LIMIT $2`, tenantID, maxEndpointsAwaitingTraffic)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rec := EndpointVerification{TenantID: tenantID, Reached: true}
			if err := rows.Scan(&rec.EndpointID, &rec.Address, &rec.Vantage, &rec.ObservedFingerprint,
				&rec.ReplacedFingerprint, &rec.ReplacedAt, &rec.TrafficUnobservedSince); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyEndpointTrafficObservedTx records the wire evidence for an endpoint
// still serving fingerprint since its replacement: when the observer saw new
// connections, and its finding. Evidence for a certificate the endpoint no
// longer serves changes nothing.
func (s *Store) ApplyEndpointTrafficObservedTx(ctx context.Context, tx pgx.Tx, tenantID, endpointID, vantage, fingerprint, findingID string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE endpoint_verifications
		    SET traffic_observed_at = $5, traffic_finding_id = $6, traffic_unobserved_since = NULL
		  WHERE tenant_id = $1 AND endpoint_id = $2 AND vantage = $3 AND observed_fingerprint = $4
		    AND replaced_at IS NOT NULL AND traffic_observed_at IS NULL`,
		tenantID, endpointID, vantage, fingerprint, at, findingID)
	return err
}

// ApplyEndpointTrafficUnobservedTx records that the window after an
// endpoint's replacement passed without wire evidence. Later evidence still
// closes it.
func (s *Store) ApplyEndpointTrafficUnobservedTx(ctx context.Context, tx pgx.Tx, tenantID, endpointID, vantage, fingerprint string, since time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE endpoint_verifications SET traffic_unobserved_since = $5
		  WHERE tenant_id = $1 AND endpoint_id = $2 AND vantage = $3 AND observed_fingerprint = $4
		    AND replaced_at IS NOT NULL AND traffic_observed_at IS NULL AND traffic_unobserved_since IS NULL`,
		tenantID, endpointID, vantage, fingerprint, since)
	return err
}
