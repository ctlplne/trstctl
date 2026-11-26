// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestHistoricalInvalidHeartbeatQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	for _, tenant := range []struct{ id, name string }{{tenantA, "Poisoned"}, {tenantB, "Healthy"}} {
		mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant.id, Data: tenantRegistered(tenant.name)})
	}
	body, err := json.Marshal(projections.AgentHeartbeat{
		ID: uuid.NewString(), Agent: "old-agent", Version: "1.0", Status: "active",
		Executors: &projections.AgentExecutorCensus{Version: "1.0", HostProfileError: strings.Repeat("x", 513)},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{Type: projections.EventAgentHeartbeat, SchemaVersion: projections.AgentHeartbeatExecutorCensusSchemaVersion,
		TenantID: tenantA, Data: body})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "later owner")})
	p := projections.New(st)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("old heartbeat blocked healthy tenant: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("old heartbeat quarantine=%v err=%v", quarantined, err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy owner count = %d", n)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("old heartbeat blocked rebuild: %v", err)
	}
}
