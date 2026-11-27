// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestReplayKeepsIdentityConflictWithinItsTenant(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered,
			TenantID: tenant, Data: tenantRegistered(tenant)}); err != nil {
			t.Fatal(err)
		}
	}
	policyID := uuid.NewString()
	for _, tenant := range []string{tenantA, tenantB} {
		data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
			ID: policyID, Name: "Tenant route", ScopeKind: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
			TenantID: tenant, Data: data}); err != nil {
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
			if _, err = st.SystemPool().Exec(ctx,
				`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantB); err == nil {
				err = proj.Rebuild(ctx, log)
			}
		}
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if count := ownerCount(t, st, tenantA); count != 1 {
			t.Fatalf("%s: operating tenant owner count=%d", mode, count)
		}
		if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantB); err != nil || !quarantined {
			t.Fatalf("%s: conflicting tenant quarantine=%t, err=%v", mode, quarantined, err)
		}
		if checkpoint, err := st.ProjectionCheckpoint(ctx); err != nil || checkpoint != last.Sequence {
			t.Fatalf("%s: checkpoint=%d, err=%v", mode, checkpoint, err)
		}
	}
}
