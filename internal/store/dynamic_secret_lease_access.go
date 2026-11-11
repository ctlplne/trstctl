// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DynamicSecretLeaseAccess is what an active dynamic-secret lease reaches, as
// its target last reported it (G2): the target, the login the lease holds
// there and that login's grants or policies. A projection of
// dynsecret.lease.access_observed, the latest observation per lease.
type DynamicSecretLeaseAccess struct {
	TenantID   string
	LeaseID    string
	Provider   string
	Status     string
	TargetKind string
	TargetRef  string
	Login      string
	Grants     []string
	Truncated  int
	// Reason is the closed-set code for an unknown or unsupported status.
	Reason string
	// CheckedAt is when this observation was recorded: the read that found it
	// changed, or the day's heartbeat (G2-L3).
	CheckedAt time.Time
	// RecheckedAt is when the worker last read the access and found it as
	// recorded; nil when the recorded read is the latest. It is the worker's
	// bookkeeping, not event-sourced, so a rebuild clears it.
	RecheckedAt *time.Time
}

// LastRead is when the lease's access was last read from its target.
func (a DynamicSecretLeaseAccess) LastRead() time.Time {
	if a.RecheckedAt != nil && a.RecheckedAt.After(a.CheckedAt) {
		return *a.RecheckedAt
	}
	return a.CheckedAt
}

// Lease access statuses. Unknown means the target could not be read; it never
// stands for "no grants".
const (
	DynamicSecretAccessResolved    = "resolved"
	DynamicSecretAccessUnknown     = "unknown"
	DynamicSecretAccessUnsupported = "unsupported"
)

// TenantsWithActiveDynamicSecretLeases lists the tenants holding an unexpired
// active lease, for the leader's access worker.
func (s *Store) TenantsWithActiveDynamicSecretLeases(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an active dynamic-secret lease so the leader-only access worker can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM dynamic_secret_leases WHERE state = 'active' AND expires_at > $1 ORDER BY 1`, now)
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

// DynamicSecretLeasesNeedingAccess returns active, unexpired leases whose
// access has not been read, was read longer ago than refresh, or was unknown
// longer ago than retry. Decoy logins (Q6) are never read: trstctl does not
// touch the bait.
func (s *Store) DynamicSecretLeasesNeedingAccess(ctx context.Context, tenantID string, now time.Time, refresh, retry time.Duration, limit int) ([]DynamicSecretLease, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: DynamicSecretLeasesNeedingAccess requires a tenant id (AN-1)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("store: DynamicSecretLeasesNeedingAccess requires a positive limit")
	}
	var out []DynamicSecretLease
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, dynamicSecretLeaseAuthoritySelect+`
			    AND state = 'active' AND expires_at > $2 AND role <> 'decoy'
			    AND NOT EXISTS (
			        SELECT 1 FROM dynamic_secret_lease_access a
			         WHERE a.tenant_id = dynamic_secret_leases.tenant_id AND a.lease_id = dynamic_secret_leases.id
			           AND ((a.status <> 'unknown' AND GREATEST(a.checked_at, a.rechecked_at) > $3)
			             OR (a.status = 'unknown' AND GREATEST(a.checked_at, a.rechecked_at) > $4)))
			  ORDER BY id
			  LIMIT $5`,
			tenantID, now, now.Add(-refresh), now.Add(-retry), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lease DynamicSecretLease
			if err := scanDynamicSecretLeaseAuthority(rows, &lease); err != nil {
				return err
			}
			out = append(out, lease)
		}
		return rows.Err()
	})
	return out, err
}

// DynamicSecretLeaseAccessFor returns the recorded access of the named leases,
// keyed by lease ID; a lease with no observation yet is absent.
func (s *Store) DynamicSecretLeaseAccessFor(ctx context.Context, tenantID string, leaseIDs []string) (map[string]DynamicSecretLeaseAccess, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: DynamicSecretLeaseAccessFor requires a tenant id (AN-1)")
	}
	out := make(map[string]DynamicSecretLeaseAccess, len(leaseIDs))
	if len(leaseIDs) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id::text, lease_id, provider, status, target_kind, target_ref, login,
			       grants, truncated, reason, checked_at, rechecked_at
			  FROM dynamic_secret_lease_access
			 WHERE tenant_id = $1 AND lease_id = ANY($2)`, tenantID, leaseIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a DynamicSecretLeaseAccess
			if err := rows.Scan(&a.TenantID, &a.LeaseID, &a.Provider, &a.Status, &a.TargetKind, &a.TargetRef,
				&a.Login, &a.Grants, &a.Truncated, &a.Reason, &a.CheckedAt, &a.RecheckedAt); err != nil {
				return err
			}
			out[a.LeaseID] = a
		}
		return rows.Err()
	})
	return out, err
}

// ApplyDynamicSecretLeaseAccessTx records an observation; an older event
// never replaces a newer one.
func (s *Store) ApplyDynamicSecretLeaseAccessTx(ctx context.Context, tx pgx.Tx, a DynamicSecretLeaseAccess, sequence uint64) error {
	if a.TenantID == "" || a.LeaseID == "" || a.Provider == "" || a.CheckedAt.IsZero() {
		return fmt.Errorf("store: dynamic-secret lease access is incomplete")
	}
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return fmt.Errorf("store: dynamic-secret lease access requires a positive int64 event sequence")
	}
	grants := a.Grants
	if grants == nil {
		grants = []string{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO dynamic_secret_lease_access
		    (tenant_id, lease_id, provider, status, target_kind, target_ref, login, grants, truncated, reason, checked_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, lease_id) DO UPDATE SET
		    provider = EXCLUDED.provider, status = EXCLUDED.status, target_kind = EXCLUDED.target_kind,
		    target_ref = EXCLUDED.target_ref, login = EXCLUDED.login, grants = EXCLUDED.grants,
		    truncated = EXCLUDED.truncated, reason = EXCLUDED.reason, checked_at = EXCLUDED.checked_at,
		    event_sequence = EXCLUDED.event_sequence, rechecked_at = NULL
		 WHERE dynamic_secret_lease_access.event_sequence < EXCLUDED.event_sequence`,
		a.TenantID, a.LeaseID, a.Provider, a.Status, a.TargetKind, a.TargetRef, a.Login, grants,
		a.Truncated, a.Reason, a.CheckedAt, int64(sequence)) // #nosec G115 -- bounded to int64 above (CWE-190)
	return err
}

// RecheckDynamicSecretLeaseAccess stamps a lease's recorded observation as
// read again, unchanged, at at (G2-L3), without an event. It stamps only the
// observation recorded at recordedAt, so a newer one recorded meanwhile is left
// alone, and reports whether it stamped.
func (s *Store) RecheckDynamicSecretLeaseAccess(ctx context.Context, tenantID, leaseID string, recordedAt, at time.Time) (bool, error) {
	if tenantID == "" || leaseID == "" {
		return false, fmt.Errorf("store: RecheckDynamicSecretLeaseAccess requires a tenant and a lease (AN-1)")
	}
	var stamped bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE dynamic_secret_lease_access SET rechecked_at = $4
			 WHERE tenant_id = $1 AND lease_id = $2 AND checked_at = $3
			   AND (rechecked_at IS NULL OR rechecked_at < $4)`, tenantID, leaseID, recordedAt, at)
		stamped = err == nil && tag.RowsAffected() == 1
		return err
	})
	return stamped, err
}
