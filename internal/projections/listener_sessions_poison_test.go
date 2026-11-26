// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestListenerSessionsRejectsUnprojectableCountBeforeAppend(t *testing.T) {
	if strconv.IntSize == 32 {
		t.Skip("Go int cannot exceed PostgreSQL integer on a 32-bit platform")
	}
	value := listenerSessionPayload()
	value.Established = int(int64(math.MaxInt32) + 1)
	if err := projections.ValidateListenerSessionsObserved(value); err == nil {
		t.Fatal("accepted a listener count larger than the PostgreSQL integer column")
	}
}

func TestHistoricalUnprojectableListenerSessionsDoesNotStopReplay(t *testing.T) {
	if strconv.IntSize == 32 {
		t.Skip("Go int cannot exceed PostgreSQL integer on a 32-bit platform")
	}
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Listener sessions tenant"}); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	bad := listenerSessionPayload()
	bad.Established = int(int64(math.MaxInt32) + 1)
	good := listenerSessionPayload()
	good.ID = "valid-listener-count"
	for _, payload := range []projections.ListenerSessionsObserved{bad, good} {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{Type: projections.EventListenerSessionsObserved, TenantID: tenantA, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return projections.New(s).ApplyTx(ctx, tx, event) }); err != nil {
			t.Fatalf("historical event %s stopped replay: %v", payload.ID, err)
		}
	}
	var count int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM listener_session_observations WHERE tenant_id = $1`, tenantA).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("projected %d observations, want only the valid event", count)
	}
}

func listenerSessionPayload() projections.ListenerSessionsObserved {
	return projections.ListenerSessionsObserved{
		ID: "poison-listener-count", TargetID: "target-1", Target: "host-1:443", Fingerprint: "abc",
		Port: 443, Established: 1, HeldByOlder: 0, Unattributed: 0, SinceUnix: 10, CheckedAtUnix: 10,
	}
}
