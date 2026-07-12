// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
)

func TestPQCRuntimeProgressRebuildAndRestartConvergeWithoutQueuedResidual(t *testing.T) {
	base := testTLSIntent()
	second := base
	second.AssetID = "asset-b"
	second.FindingKind = "cipher"
	second.AssetProtocol = ""
	second.Cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	started := projections.LicensedCryptoMigrationStarted{
		RunID: base.RunID, AssetIDs: []string{base.AssetID, second.AssetID},
		TargetAlgorithm: TargetMLDSA65, EffectiveAlgorithm: EffectiveHybridTLS,
		Protocol: ProtocolACME, Queued: 2,
		TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{base, second},
	}
	completed := TLSFindingCompleted{
		Intent: base,
		Receipt: connector.TLSPostureReceipt{
			RunID: base.RunID, FindingID: base.AssetID, FindingKind: base.FindingKind,
			TargetID: base.TargetID, TargetRevision: base.TargetRevision, Connector: base.Connector,
			Previous: connector.TLSPosture{
				MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
				KeyExchangeGroups: []string{"secp256r1"},
			},
			Observed: base.Desired, Applied: true,
		},
	}
	prepared := TLSFindingPrepared{
		RunID: base.RunID, AssetID: base.AssetID, FindingKind: base.FindingKind,
		TargetID: base.TargetID, TargetRevision: base.TargetRevision, Connector: base.Connector,
		Previous: completed.Receipt.Previous,
	}
	failed := TLSFindingFailure{
		RunID: second.RunID, AssetID: second.AssetID, FindingKind: second.FindingKind,
		TargetID: second.TargetID, Connector: second.Connector,
		Reason: "TLS posture delivery attempts exhausted", Status: TLSFindingFailed,
	}
	when := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	log := []events.Event{
		{Type: projections.EventLicensedCryptoMigrationStarted, TenantID: sealedTestTenant, Time: when, Data: mustJSON(t, started)},
		{Type: EventTLSFindingPrepared, TenantID: sealedTestTenant, Time: when.Add(time.Second), Data: mustJSON(t, prepared)},
		{Type: EventTLSFindingCompleted, TenantID: sealedTestTenant, Time: when.Add(2 * time.Second), Data: mustJSON(t, completed)},
		{Type: EventTLSFindingFailed, TenantID: sealedTestTenant, Time: when.Add(3 * time.Second), Data: mustJSON(t, failed)},
	}

	first := testProgressRuntime()
	applyProgressLog(t, first.Progress, log)
	want := first.Progress.Snapshot(sealedTestTenant, base.RunID)
	assertNoQueuedResidual(t, want)

	if err := first.Progress.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	applyProgressLog(t, first.Progress, log)
	if got := first.Progress.Snapshot(sealedTestTenant, base.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("same-runtime rebuild diverged:\n got=%+v\nwant=%+v", got, want)
	}

	restarted := testProgressRuntime()
	applyProgressLog(t, restarted.Progress, log)
	if got := restarted.Progress.Snapshot(sealedTestTenant, base.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh-runtime replay diverged:\n got=%+v\nwant=%+v", got, want)
	}
}

func testProgressRuntime() *Runtime {
	runtime := NewRuntime(nil)
	runtime.Progress.projectCompletedHook = func(context.Context, eventspec.Event, TLSFindingCompleted) error { return nil }
	runtime.Progress.projectRollbackHook = func(context.Context, eventspec.Event, TLSFindingRollbackCompleted) error { return nil }
	return runtime
}

func applyProgressLog(t *testing.T, projection *ProgressProjection, log []events.Event) {
	t.Helper()
	for _, event := range log {
		if err := projection.Apply(context.Background(), event); err != nil {
			t.Fatalf("apply %s: %v", event.Type, err)
		}
	}
}

func assertNoQueuedResidual(t *testing.T, items []FindingProgress) {
	t.Helper()
	if len(items) != 2 {
		t.Fatalf("progress items = %d, want 2", len(items))
	}
	statuses := map[string]int{}
	for _, item := range items {
		statuses[item.Status]++
		if item.Status == TLSFindingQueued {
			t.Fatalf("terminal batch retained unresolved queued finding: %+v", item)
		}
	}
	if statuses[TLSFindingApplied] != 1 || statuses[TLSFindingFailed] != 1 {
		t.Fatalf("terminal statuses = %v, want one applied and one failed", statuses)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
