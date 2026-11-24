// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantPoisonQuarantineSeesPeerAfterEarlierHealthyEvent(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, os.Getenv("TRSTCTL_STORE_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	q := newTenantPoisonQuarantine(st)
	first := events.Event{Sequence: 1, Type: EventOwnerCreated, TenantID: tenant, Data: json.RawMessage(`{}`)}
	if skip, err := q.skip(ctx, first); err != nil || skip {
		t.Fatalf("initial healthy event skipped=%v err=%v", skip, err)
	}
	// A second projector can discover an older poisoned event after this worker
	// cached a healthy answer. Its durable quarantine must take effect here.
	if err := st.RecordProjectionTenantQuarantine(ctx, tenant, 1, "nul_text"); err != nil {
		t.Fatal(err)
	}
	second := events.Event{Sequence: 2, Type: EventOwnerCreated, TenantID: tenant, Data: json.RawMessage(`{}`)}
	if skip, err := q.skip(ctx, second); err != nil || !skip {
		t.Fatalf("peer quarantine not observed: skipped=%v err=%v", skip, err)
	}
}

func TestTenantPoisonQuarantineRechecksAfterOffboard(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, os.Getenv("TRSTCTL_STORE_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const tenant = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordProjectionTenantQuarantine(ctx, tenant, 2, "nul_text"); err != nil {
		t.Fatal(err)
	}
	q := newTenantPoisonQuarantine(st)
	offboard := events.Event{Sequence: 3, Type: EventTenantOffboarded, TenantID: tenant,
		Data: json.RawMessage(`{"rows_deleted":1}`)}
	if skip, err := q.skip(ctx, offboard); err != nil || skip {
		t.Fatalf("key-custody offboard skipped=%v err=%v", skip, err)
	}
	// OffboardTenant removes the marker with the rest of its tenant rows. A
	// later registration of the same UUID starts a new lifecycle in the log.
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	registered := events.Event{Sequence: 4, Type: EventTenantRegistered, TenantID: tenant,
		Data: json.RawMessage(`{"name":"new lifecycle"}`)}
	if skip, err := q.skip(ctx, registered); err != nil || skip {
		t.Fatalf("fresh registration after offboard skipped=%v err=%v", skip, err)
	}
}
