// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// CR-045: the exact raw history publisher must leave durable, target-local
// record evidence. A successful restore may clear its fence only after every
// published event has a verified journal row.
func TestFullRestoreRetainsVerifiedRawHistoryJournalCR045(t *testing.T) {
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	result, err := runFullRestore(t.Context(), target, info.Directory, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.EventsRestored == 0 {
		t.Fatal("fixture restored no events")
	}
	st, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var live, binding, indexes, unbinding int
	//trstctl:system-query — recovery proof coverage across the one disposable target is checked by the test's owner role.
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE action='live'),
		count(*) FILTER (WHERE action='bind'),
		count(*) FILTER (WHERE action='index'),
		count(*) FILTER (WHERE action='unbind')
		FROM trstctl_recovery.raw_history_journal WHERE phase='verified'`).
		Scan(&live, &binding, &indexes, &unbinding); err != nil {
		t.Fatalf("read target-local raw history journal: %v", err)
	}
	if live < result.EventsRestored || binding != 1 || indexes != 1 || unbinding != 1 {
		t.Fatalf("verified raw journal live=%d bind=%d index=%d unbind=%d, restored events=%d",
			live, binding, indexes, unbinding, result.EventsRestored)
	}
}
