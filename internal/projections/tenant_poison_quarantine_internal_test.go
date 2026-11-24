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
