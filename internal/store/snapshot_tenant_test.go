// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestSnapshotRestoreRejectsMissingOrForeignTenantRegistration(t *testing.T) {
	for _, scenario := range []struct{ name, expression string }{
		{"missing", `payload - 'tenants'`},
		{"null", `jsonb_set(payload,'{tenants}','null'::jsonb)`},
		{"empty", `jsonb_set(payload,'{tenants}','[]'::jsonb)`},
		{"neighbor", `jsonb_set(payload,'{tenants,0,tenant_id}',to_jsonb($2::text))`},
		{"duplicate", `jsonb_set(payload,'{tenants}',(payload->'tenants') || (payload->'tenants'))`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s := newStore(t)
			ctx := t.Context()
			seedTwoTenants(t, s)
			before, err := s.GetTenant(ctx, tenantA)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := s.WriteReadModelSnapshots(ctx); err != nil || n != 2 {
				t.Fatalf("capture=%d error=%v", n, err)
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				args := []any{tenantA}
				if scenario.name == "neighbor" {
					args = append(args, tenantB)
				}
				_, err := tx.Exec(ctx, "UPDATE read_model_snapshots SET payload="+scenario.expression+" WHERE tenant_id=$1", args...)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			err = s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error { _, err := s.RestoreSnapshotsTx(ctx, tx); return err })
			if err == nil {
				t.Error("restore accepted a snapshot without one exact tenant registration")
			}
			after, err := s.GetTenant(ctx, tenantA)
			if err != nil || before.Name != after.Name || before.EventSeq != after.EventSeq || !before.CreatedAt.Equal(after.CreatedAt) {
				t.Errorf("failed restore changed live registration: %+v error=%v", after, err)
			}
			if _, err := s.GetTenant(ctx, tenantB); err != nil {
				t.Errorf("failed restore lost neighbor: %v", err)
			}
		})
	}
}

// An ordinary caller's erased flag cannot select a generation for disposal.
func TestBareSnapshotErasureMarkerCannotDiscardACacheGeneration(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	if count, err := s.WriteReadModelSnapshots(t.Context()); err != nil || count != 2 {
		t.Fatalf("capture: %d %v", count, err)
	}
	if err := s.DiscardErasedSnapshotGeneration(t.Context(), store.ErrSnapshotErased); err == nil {
		t.Fatal("a bare erased marker selected cache rows")
	}
	if count, err := s.SnapshotCount(t.Context()); err != nil || count != 2 {
		t.Fatalf("rejected marker changed cache: %d %v", count, err)
	}
}
