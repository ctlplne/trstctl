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

func TestHistoricalJSONBPoisonQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, os.Getenv("TRSTCTL_STORE_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const poisoned = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	const healthy = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if _, err := st.SystemPool().Exec(ctx, `DELETE FROM projection_tenant_quarantines WHERE tenant_id IN ($1,$2)`, poisoned, healthy); err != nil {
		t.Fatal(err)
	}
	q := newTenantPoisonQuarantine(st)
	for _, data := range []string{`{"attributes":{"x":"\ud800"}}`, `{"attributes":{"n":1e999999}}`} {
		var projected string
		if err := st.SystemPool().QueryRow(ctx, `SELECT $1::jsonb::text`, data).Scan(&projected); err == nil {
			t.Fatalf("PostgreSQL accepted poison JSONB payload: %s", data)
		}
		event := events.Event{Sequence: 10, Type: EventIdentityCreated, TenantID: poisoned, Data: []byte(data)}
		if skip, err := q.skip(ctx, event); err != nil || !skip {
			t.Fatalf("historical JSONB poison skipped=%v err=%v", skip, err)
		}
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, poisoned); err != nil || !quarantined {
		t.Fatalf("poisoned tenant quarantine=%v err=%v", quarantined, err)
	}
	const malformedFindingTenant = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	findingData, err := json.Marshal(DiscoveryFindingRecorded{
		Kind: "api_key", Ref: "service", RiskScore: 95, Metadata: json.RawMessage(`[]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if skip, err := q.skip(ctx, events.Event{Sequence: 12, Type: EventDiscoveryFindingRecorded, TenantID: malformedFindingTenant, Data: findingData}); err != nil || !skip {
		t.Fatalf("historical urgent finding with non-object metadata skipped=%v err=%v", skip, err)
	}
	event := events.Event{Sequence: 11, Type: EventIdentityCreated, TenantID: healthy, Data: []byte(`{"attributes":{}}`)}
	if skip, err := q.skip(ctx, event); err != nil || skip {
		t.Fatalf("healthy tenant skipped=%v err=%v", skip, err)
	}
}
