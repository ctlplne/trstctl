// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestHistoricalSwitchingRowWithYearZeroReplays(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedAgentJobTenant(t, ctx, st, tenantA)
	id := gouuid.NewString()
	now := time.Now().UTC()
	err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplySwitchingImportStartedTx(ctx, tx, tenantA, store.SwitchingImport{
			ID: id, Name: "fixture", Format: "trstctl.switching-export/v1", PreviewDigest: "fixture",
			RowsTotal: 1, Counts: map[string]int{"expired": 1}, GapCounts: map[string]int{},
			CreatedBy: "operator", CreatedAt: now,
		}, 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	invalid := time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)
	err = st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplySwitchingImportRowsRecordedTx(ctx, tx, tenantA, id, []store.SwitchingImportRow{{
			Row: 1, Outcome: "expired", Reason: "expired 0000-01-01", NotAfter: &invalid,
		}}, 2)
	})
	if err != nil {
		t.Fatalf("historical year-zero row blocked projection replay: %v", err)
	}
	rows, err := st.ListSwitchingImportRows(ctx, tenantA, id, "", "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].NotAfter != nil {
		t.Fatalf("historical invalid expiry was stored: %+v", rows)
	}
}
