// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Old event logs can already contain a malformed ring assignment. Replay must
// advance past it without letting one tenant stop projection for every tenant.
func TestAgentUpgradeRingReplayAbsorbsHistoricalInvalidAgentID(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Agent upgrade tenant"}); err != nil {
		t.Fatal(err)
	}
	log := openLog(t)
	data, err := json.Marshal(projections.AgentUpgradeRingAssigned{AgentID: "not-a-uuid", Ring: "canary"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(ctx, events.Event{Type: projections.EventAgentUpgradeRingAssigned, TenantID: tenantA, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	proj := projections.New(s)
	for i := 0; i < 2; i++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return proj.ApplyTx(ctx, tx, event) }); err != nil {
			t.Fatalf("replay %d blocked by historical malformed agent ID: %v", i, err)
		}
	}
}
