// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
)

func TestHostReceiptIndexColdReplayTenantIsolationAndReset(t *testing.T) {
	ctx := context.Background()
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.2"}
	desired := connector.TLSPosture{MinimumVersion: "TLSv1.3",
		KeyExchangeGroups: []string{HybridTLSGroup}}
	prepared := TLSFindingPrepared{RunID: "run-a", AssetID: "asset-a", TargetID: "target-a",
		TargetRevision: "revision-a", Connector: "envoy", Previous: previous}
	completed := TLSFindingCompleted{
		Intent: pqcMigrationTLSPosturePayload{RunID: "run-a", AssetID: "asset-a",
			TargetID: "target-a", TargetRevision: "revision-a", Connector: "envoy", Desired: desired},
		Receipt:        connector.TLSPostureReceipt{TargetID: "target-a", Previous: previous, Observed: desired},
		EvidenceDigest: "signed-forward",
	}
	rollback := TLSFindingRollbackCompleted{RunID: "run-a",
		Restores:       []TLSAssetRestore{{AssetID: "asset-a", TargetID: "target-a"}},
		Receipt:        connector.TLSPostureReceipt{TargetID: "target-a", Previous: desired, Observed: previous},
		EvidenceDigest: "signed-rollback"}
	makeEvent := func(sequence uint64, eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{ID: hostReceiptEventID("tenant-a", "run-a", "asset-a", eventType),
			Sequence: sequence, TenantID: "tenant-a", Type: eventType, Data: data}
	}
	eventsToReplay := []events.Event{
		makeEvent(4100, EventTLSFindingPrepared, prepared),
		makeEvent(4101, EventTLSFindingCompleted, completed),
		makeEvent(4102, EventTLSFindingRollbackCompleted, rollback),
	}
	for replay := 0; replay < 2; replay++ {
		p := NewProgressProjection(nil)
		p.projectCompletedHook = func(context.Context, events.Event, TLSFindingCompleted) error { return nil }
		p.projectRollbackHook = func(context.Context, events.Event, TLSFindingRollbackCompleted) error { return nil }
		for _, event := range eventsToReplay {
			if err := p.Apply(ctx, event); err != nil {
				t.Fatal(err)
			}
		}
		if got, found, err := p.hostPreparedReceipt("tenant-a", "run-a", "asset-a"); err != nil || !found ||
			got.TargetRevision != "revision-a" || got.Previous.MinimumVersion != "TLSv1.2" {
			t.Fatalf("prepared predecessor after replay = %+v found=%v err=%v", got, found, err)
		}
		if got, found, err := p.hostCompletedReceipt("tenant-a", "run-a", "asset-a"); err != nil || !found ||
			got.EvidenceDigest != "signed-forward" || got.Intent.TargetID != "target-a" {
			t.Fatalf("signed completion after replay = %+v found=%v err=%v", got, found, err)
		}
		if got, found, err := p.hostRollbackReceipt("tenant-a", "run-a", "target-a"); err != nil || !found ||
			got.EvidenceDigest != "signed-rollback" {
			t.Fatalf("signed rollback after replay = %+v found=%v err=%v", got, found, err)
		}
		if _, found, err := p.hostCompletedReceipt("tenant-b", "run-a", "asset-a"); err != nil || found {
			t.Fatalf("cross-tenant receipt visible: found=%v err=%v", found, err)
		}
		p.retainPendingHostReceipt(eventsToReplay[1])
		if err := p.Reset(ctx); err != nil {
			t.Fatal(err)
		}
		if _, found, err := p.hostCompletedReceipt("tenant-a", "run-a", "asset-a"); err != nil || found {
			t.Fatalf("reset retained completion: found=%v err=%v", found, err)
		}
		if _, found := p.pendingHostReceipt(eventsToReplay[1].ID); found {
			t.Fatal("reset retained an unprojected in-process event")
		}
	}
	if hostReceiptEventID("tenant-a", "run-a", "asset-a", EventTLSFindingCompleted) ==
		hostReceiptEventID("tenant-b", "run-a", "asset-a", EventTLSFindingCompleted) {
		t.Fatal("receipt IDs must bind the tenant")
	}
}
