// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"math"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestProjectionTenantQuarantineIsDurableTenantScopedAndFirstWriterWins(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	for _, tenant := range []string{tenantA, tenantB} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "quarantine fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordProjectionTenantQuarantine(ctx, tenantA, 3, "nul_text"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordProjectionTenantQuarantine(ctx, tenantA, 9, "invalid_utf8"); err != nil {
		t.Fatal(err)
	}
	var first int64
	var reason string
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT first_failed_seq, reason_code FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA,
	).Scan(&first, &reason); err != nil {
		t.Fatal(err)
	}
	if first != 3 || reason != "nul_text" {
		t.Errorf("quarantine changed from first failure: sequence=%d reason=%q", first, reason)
	}
	if err := st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA,
		).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Errorf("tenant B can read tenant A quarantine: %d", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO projection_tenant_quarantines (tenant_id, first_failed_seq, reason_code) VALUES ($1,$2,$3)`,
			tenantA, 10, "nul_text")
		return err
	}); err == nil {
		t.Error("tenant B wrote tenant A quarantine through app role")
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); err == nil {
		t.Error("quarantined tenant A remained serviceable")
	}
	if err := st.RequireLiveTenantService(ctx, tenantB); err != nil {
		t.Errorf("healthy tenant B refused: %v", err)
	}
	if err := st.RecordProjectionTenantQuarantine(ctx, tenantB, uint64(math.MaxInt64)+1, "nul_text"); err == nil {
		t.Error("sequence beyond PostgreSQL bigint accepted")
	}
}
