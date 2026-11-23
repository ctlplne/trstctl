// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Recovery key snapshots are target-local proof material. They must never let
// a tenant read or plant another tenant's key-domain snapshot through the app
// role, and each lookup is bound to the exact restore/rebuild operation.
func TestRewrapRecoveryKeySnapshotsAreTenantAndOperationScoped(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009701"
	const otherOperation = "a7770000-0000-4000-8000-000000009702"
	const eventID = "a7770000-0000-4000-8000-000000009703"
	if err := s.StageTenantKeyRecoveryLifecycle(ctx, operation, tenantA,
		"a7770000-0000-4000-8000-000000009704", 1, true); err != nil {
		t.Fatal(err)
	}
	if err := s.StageTenantKeyRecoverySnapshot(ctx, operation, store.TenantKeyDomain{
		TenantID: tenantA, DomainID: "a7770000-0000-4000-8000-000000009705",
		LastTransitionEventID: eventID, LastTransitionSequence: 2,
	}); err != nil {
		t.Fatalf("stage tenant A snapshot: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation).Scan(&count); err != nil {
			return err
		}
		if count != 2 {
			t.Fatalf("tenant A staged rows=%d, want registration and key snapshot", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.tenant_key_domain_snapshots
			(tenant_id,operation_id,event_id,source_sequence,snapshot_sha256,snapshot)
			VALUES ($1,$2,$3,3,$4,'{}'::jsonb)`, tenantA, operation,
			"a7770000-0000-4000-8000-000000009706", strings.Repeat("a", 64))
		return err
	}); err == nil {
		t.Fatal("application role wrote its own recovery authority")
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("tenant B read tenant A recovery snapshot: %d", count)
		}
		if _, err := tx.Exec(ctx, `SAVEPOINT cross_tenant_snapshot`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.tenant_key_domain_snapshots
			(tenant_id,operation_id,event_id,source_sequence,snapshot_sha256,snapshot)
			VALUES ($1,$2,$3,1,$4,'{}'::jsonb)`, tenantA, otherOperation, eventID, strings.Repeat("b", 64))
		if err == nil {
			t.Fatal("tenant B planted a tenant A recovery snapshot")
		}
		_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cross_tenant_snapshot`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.tenant_key_domain_snapshots
			WHERE tenant_id=$1 AND operation_id=$2`, tenantA, otherOperation).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("another operation's snapshot appeared in tenant A: %d", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
