// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestReplayPreservesHeldRoutingNameWithinTenant(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
			TenantID: tenant, Data: tenantRegistered(tenant)}); err != nil {
			t.Fatal(err)
		}
	}
	firstPolicyID, laterPolicyID := uuid.NewString(), uuid.NewString()
	for _, id := range []string{firstPolicyID, laterPolicyID} {
		data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
			ID: id, Name: "Tenant route", ScopeKind: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
			TenantID: tenantB, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	last, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated,
		TenantID: tenantA, Data: ownerCreated("00000000-0000-4000-8000-0000000000a1", "owner")})
	if err != nil {
		t.Fatal(err)
	}
	proj := projections.New(st)
	for _, mode := range []string{"catch-up", "rebuild"} {
		var err error
		if mode == "catch-up" {
			err = proj.ProjectCatchUp(ctx, log)
		} else {
			err = proj.Rebuild(ctx, log)
		}
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if count := ownerCount(t, st, tenantA); count != 1 {
			t.Fatalf("%s: operating tenant owner count=%d", mode, count)
		}
		if policy, err := st.GetNotificationRoutingPolicy(ctx, tenantB, firstPolicyID); err != nil || policy.Name != "Tenant route" {
			t.Fatalf("%s: held policy=%+v, err=%v", mode, policy, err)
		}
		if _, err := st.GetNotificationRoutingPolicy(ctx, tenantB, laterPolicyID); !store.IsNotFound(err) {
			t.Fatalf("%s: later policy was projected: %v", mode, err)
		}
		if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantB); err != nil || quarantined {
			t.Fatalf("%s: tenant quarantine=%t, err=%v", mode, quarantined, err)
		}
		if checkpoint, err := st.ProjectionCheckpoint(ctx); err != nil || checkpoint != last.Sequence {
			t.Fatalf("%s: checkpoint=%d, err=%v", mode, checkpoint, err)
		}
	}
}
