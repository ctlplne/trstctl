// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestFailedArchiveHoldReleaseHasStableRetryCommandsAcrossReadModelRebuild(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	const id = "a2080000-0000-4000-8000-0000000007f1"
	object := "tenant/" + tenantA + "/audit/recovery.jws"
	at := time.Now().UTC()
	apply := func(fn func(pgx.Tx) error) {
		t.Helper()
		if err := s.WithTenant(t.Context(), tenantA, fn); err != nil {
			t.Fatal(err)
		}
	}
	replay := func() {
		apply(func(tx pgx.Tx) error {
			return s.PlaceArchiveLegalHoldTx(t.Context(), tx, store.ArchiveLegalHold{TenantID: tenantA, ID: id, Object: object, Reason: "fixture legal hold", PlacedAt: at, EventSequence: 1})
		})
		apply(func(tx pgx.Tx) error {
			return s.RecordArchiveLegalHoldOutcomeTx(t.Context(), tx, tenantA, id, "applied", "", at, 2)
		})
		apply(func(tx pgx.Tx) error { return s.RequestArchiveLegalHoldReleaseTx(t.Context(), tx, tenantA, id, at, 3) })
		apply(func(tx pgx.Tx) error {
			return s.RecordArchiveLegalHoldOutcomeTx(t.Context(), tx, tenantA, id, "failed", "fixture interruption", at, 4)
		})
		apply(func(tx pgx.Tx) error { return s.RequestArchiveLegalHoldReleaseTx(t.Context(), tx, tenantA, id, at, 5) })
		hold, err := s.GetArchiveLegalHold(t.Context(), tenantA, id)
		if err != nil || hold.Status != "release_pending" {
			t.Fatalf("failed hold did not get a fresh release attempt: status=%s err=%v", hold.Status, err)
		}
		apply(func(tx pgx.Tx) error {
			return s.RecordArchiveLegalHoldOutcomeTx(t.Context(), tx, tenantA, id, "released", "", at, 6)
		})
	}
	commands := func() []string {
		t.Helper()
		var out []string
		apply(func(tx pgx.Tx) error {
			rows, err := tx.Query(t.Context(), `SELECT id::text||':'||idempotency_key||':'||status||':'||payload::text FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key LIKE $3 ORDER BY id`, tenantA, store.ArchiveLegalHoldDestination, "archive-legal-hold:"+id+":%")
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var value string
				if err := rows.Scan(&value); err != nil {
					return err
				}
				out = append(out, value)
			}
			return rows.Err()
		})
		return out
	}
	replay()
	before := commands()
	if len(before) != 3 {
		t.Fatalf("expected initial set, initial release and a distinct retry command; got %d", len(before))
	}
	// Model the read-model table being cleared during rebuild; retain operational
	// outbox evidence exactly as real rebuild does. This is fixture reset only.
	apply(func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM archive_legal_holds WHERE tenant_id=$1 AND id=$2`, tenantA, id)
		return err
	})
	replay()
	after := commands()
	if len(after) != len(before) {
		t.Fatalf("rebuild duplicated old release effects: before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("rebuild changed an original delivery command or its evidence")
		}
	}
}
