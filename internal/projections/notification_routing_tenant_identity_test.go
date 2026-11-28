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

func TestNotificationRoutingPolicyIdentityIsTenantScopedThroughReplay(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	policyID := uuid.NewString()
	for _, tc := range []struct{ tenant, name string }{
		{tenantA, "Primary route"},
		{tenantB, "Independent route"},
	} {
		if _, err := log.Append(ctx, events.Event{
			Type: projections.EventTenantRegistered, TenantID: tc.tenant, Data: tenantRegistered(tc.name),
		}); err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
			ID: policyID, Name: tc.name, ScopeKind: "manual",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: tc.tenant, Data: payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	projector := projections.New(st)
	assertPolicies := func(stage string) {
		t.Helper()
		for _, tc := range []struct{ tenant, name string }{
			{tenantA, "Primary route"},
			{tenantB, "Independent route"},
		} {
			policy, err := st.GetNotificationRoutingPolicy(ctx, tc.tenant, policyID)
			if err != nil || policy.Name != tc.name || policy.TenantID != tc.tenant {
				t.Fatalf("%s policy %s: value=%+v err=%v", stage, tc.tenant, policy, err)
			}
		}
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up tenant-local routing policies: %v", err)
	}
	assertPolicies("catch-up")
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild tenant-local routing policies: %v", err)
	}
	assertPolicies("rebuild")
}
