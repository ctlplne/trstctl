// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestHistoricalOversizedNativeFailureReceiptQuarantinesOnlyItsTenantN0010(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	for _, tenant := range []struct{ id, name string }{{tenantA, "Poisoned"}, {tenantB, "Healthy"}} {
		mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant.id, Data: tenantRegistered(tenant.name)})
	}
	for _, kind := range []string{projections.EventWindowsLocalAccountScanFailed, projections.EventServiceDependentScanFailed} {
		body, err := json.Marshal(projections.ServiceDependentScanFailed{
			RunID: uuid.NewString(), JobID: 5, Attempt: 1, Reason: "agent_execution_failed",
			ReceiptStatement: strings.Repeat("e", 33<<10), ReceiptSignature: "c2ln",
			SignerFingerprint: strings.Repeat("a", 64), At: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: kind, SchemaVersion: 1, TenantID: tenantA, Data: body})
	}
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantB, Data: ownerCreated(uuid.NewString(), "later owner")})
	p := projections.New(st)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("historical bad receipt blocked healthy tenant: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("quarantine=%v err=%v", quarantined, err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy tenant has %d owners", n)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("historical bad receipt blocked rebuild: %v", err)
	}
}
