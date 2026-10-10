// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestTLSReceiptWorkerIndexedRecoveryAcrossColdRestart(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	appendFact := func(tenantID, eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: eventType, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}

	intent := testTLSIntent()
	sealed := sealTestIntent(t, testIntegrityKey(t), intent)
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.0",
		CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}, KeyExchangeGroups: []string{"secp256r1"}}
	prepared := TLSFindingPrepared{RunID: intent.RunID, AssetID: intent.AssetID,
		FindingKind: intent.FindingKind, TargetID: intent.TargetID,
		TargetRevision: intent.TargetRevision, Connector: intent.Connector, Previous: previous}
	eventIntent := intent
	eventIntent.TargetConfig = nil
	eventIntent.SealedOutboxPayload = append(json.RawMessage(nil), sealed...)
	completed := TLSFindingCompleted{Intent: eventIntent, Receipt: connector.TLSPostureReceipt{
		RunID: intent.RunID, FindingID: intent.AssetID, FindingKind: intent.FindingKind,
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision,
		Connector: intent.Connector, Previous: previous, Observed: intent.Desired, Applied: true}}
	appendFact("other-tenant", EventTLSFindingPrepared, prepared)
	appendFact(sealedTestTenant, "unrelated.event", map[string]string{"noise": "before"})
	start := appendFact(sealedTestTenant, projections.EventLicensedCryptoMigrationStarted,
		projections.LicensedCryptoMigrationStarted{RunID: intent.RunID})
	appendFact("other-tenant", EventTLSFindingCompleted, completed)
	appendFact(sealedTestTenant, EventTLSFindingPrepared, prepared)
	appendFact(sealedTestTenant, "unrelated.event", map[string]string{"noise": "between"})
	appendFact(sealedTestTenant, EventTLSFindingCompleted, completed)

	readBack := func(progress *ProgressProjection) {
		t.Helper()
		h := &outboxHandler{log: log, progress: progress}
		gotPrevious, found, err := h.preparedTLSPosture(ctx, sealedTestTenant, intent)
		if err != nil || !found || !connector.EqualTLSPosture(gotPrevious, previous) {
			t.Fatalf("prepared receipt found=%v previous=%+v err=%v", found, gotPrevious, err)
		}
		gotCompleted, found, err := h.completedTLSFinding(ctx, sealedTestTenant, intent, sealed)
		if err != nil || !found || !connector.EqualTLSPosture(gotCompleted.Receipt.Observed, intent.Desired) {
			t.Fatalf("completed receipt found=%v completed=%+v err=%v", found, gotCompleted, err)
		}
		if _, found, err := h.preparedTLSPosture(ctx, "other-tenant-without-facts", intent); err != nil || found {
			t.Fatalf("cross-tenant prepared receipt found=%v err=%v", found, err)
		}
	}
	progress := NewProgressProjection(nil)
	if err := progress.Apply(ctx, start); err != nil {
		t.Fatal(err)
	}
	readBack(progress)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	coldStart, found, err := log.EventAtSequence(ctx, start.Sequence)
	if err != nil || !found {
		t.Fatalf("cold start found=%v err=%v", found, err)
	}
	coldProgress := NewProgressProjection(nil)
	if err := coldProgress.Apply(ctx, coldStart); err != nil {
		t.Fatal(err)
	}
	readBack(coldProgress)
	readBack(NewProgressProjection(nil)) // a replica whose projector is behind

	conflictingPrepared := prepared
	conflictingPrepared.Previous.MinimumVersion = "TLSv1.1"
	appendFact(sealedTestTenant, EventTLSFindingPrepared, conflictingPrepared)
	h := &outboxHandler{log: log, progress: coldProgress}
	if _, _, err := h.preparedTLSPosture(ctx, sealedTestTenant, intent); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting prepared predecessor was accepted: %v", err)
	}
	conflictingCompleted := completed
	conflictingCompleted.Receipt.Previous = conflictingPrepared.Previous
	appendFact(sealedTestTenant, EventTLSFindingCompleted, conflictingCompleted)
	if _, _, err := h.completedTLSFinding(ctx, sealedTestTenant, intent, sealed); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting completed predecessor was accepted: %v", err)
	}
}
