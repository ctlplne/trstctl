// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Pair proof belongs to the same transaction as TRUNCATE and replay, but must
// run while the previous read model still exists. A replay failure rolls back
// both the read-model replacement and its unconsumed proof rows.
func TestRebuildPairPreflightRunsBeforeTruncateAndRollsBackAtomically(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009731"
	const eventID = "a7770000-0000-4000-8000-000000009732"
	intentional := errors.New("stop after truncate")
	err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		return s.RebuildReadModelWithPreflightTx(admitted,
			func(tx pgx.Tx) error {
				var count int
				if err := tx.QueryRow(admitted, `SELECT count(*) FROM tenants WHERE tenant_id=$1`, tenantA).Scan(&count); err != nil {
					return err
				}
				if count != 1 {
					t.Fatalf("preflight saw tenant count %d, want old read model", count)
				}
				_, err := tx.Exec(admitted, `INSERT INTO trstctl_recovery.recovery_pair_proofs
					(tenant_id,operation_id,event_id,pair_kind,row_id,event_sha256,row_sha256,key_state_sha256)
					VALUES ($1,$2,$3,'receipt',$3,$4,$4,$4)`, tenantA, operation, eventID,
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				return err
			},
			func(tx pgx.Tx) error {
				var count int
				if err := tx.QueryRow(admitted, `SELECT count(*) FROM tenants WHERE tenant_id=$1`, tenantA).Scan(&count); err != nil {
					return err
				}
				if count != 0 {
					t.Fatalf("apply saw old tenant count %d, want truncated model", count)
				}
				return intentional
			})
	})
	if !errors.Is(err, intentional) {
		t.Fatalf("rebuild result=%v, want deliberate replay error", err)
	}
	var tenantCount, proofCount int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM tenants WHERE tenant_id=$1`, tenantA).Scan(&tenantCount); err != nil {
		t.Fatal(err)
	}
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM trstctl_recovery.recovery_pair_proofs
		WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation).Scan(&proofCount); err != nil {
		t.Fatal(err)
	}
	if tenantCount != 1 || proofCount != 0 {
		t.Fatalf("rollback left tenant=%d proof=%d, want old model and no proof", tenantCount, proofCount)
	}
}
