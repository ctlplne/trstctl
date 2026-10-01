// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestEndpointVerificationAlertSnapshotKeepsClosedVersionedShape(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	observed := EndpointVerificationObservedWithAlert{
		EndpointVerificationObserved: EndpointVerificationObserved{
			EndpointID: "qa-db", Address: "db.example.test:5432", Vantage: "relay", ObservedAt: now,
		}, AlertRequired: true, AlertLastGoodAt: now.Add(-time.Minute),
	}
	wire, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	ev := events.Event{ID: "qa-alert-snapshot", TenantID: "11111111-1111-4111-8111-111111111111", Type: EventEndpointVerified, SchemaVersion: EndpointVerificationAlertEventSchemaVersion, Data: wire}
	retained, err := log.Append(t.Context(), ev)
	if err != nil {
		t.Fatalf("valid failed observation lost its alert snapshot: %v", err)
	}
	var decoded EndpointVerificationObservedWithAlert
	if err := json.Unmarshal(retained.Data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.AlertRequired || !decoded.AlertLastGoodAt.Equal(observed.AlertLastGoodAt) || !decoded.NotBefore.IsZero() || !decoded.NotAfter.IsZero() {
		t.Fatalf("snapshot was changed or invented a served certificate: %+v", decoded)
	}
	ev.ID, ev.SchemaVersion = "qa-alert-invalid-legacy", 1
	if _, err := log.Append(t.Context(), ev); err == nil {
		t.Fatal("legacy schema accepted new notification authority")
	}
	ev.SchemaVersion = EndpointVerificationAlertEventSchemaVersion
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { delete(v, "alert_required") },
		func(v map[string]any) { v["alert_last_good_at"] = 42 },
		func(v map[string]any) { v["unregistered_notification"] = "unexpected" },
	} {
		var fields map[string]any
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		mutate(fields)
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		ev.ID, ev.Data = ev.ID+"-invalid", data
		if _, err := log.Append(t.Context(), ev); err == nil {
			t.Fatal("closed alert shape accepted missing, malformed or unknown authority")
		}
	}
	observed.AlertRequired = false
	wire, err = json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	ev.Data = wire
	if _, err := decodeEndpointVerificationObserved(ev); err == nil {
		t.Fatal("projector accepted a failed observation with a contradictory alert decision")
	}
}

func TestEndpointVerificationHistoricalAlertVersionAndSupersededDecision(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	observed := EndpointVerificationObservedWithAlert{
		EndpointVerificationObserved: EndpointVerificationObserved{
			EndpointID: "renewed-listener", Address: "127.0.0.1:18443", Vantage: "relay",
			Reached: true, Mismatch: "fingerprint", ExpectedFingerprint: "old", ObservedFingerprint: "new",
		},
		AlertRequired: true,
	}
	oldWire, err := json.Marshal(endpointVerificationObservedWithAlertV2{EndpointVerificationObserved: observed.EndpointVerificationObserved, AlertRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	old, err := log.Append(t.Context(), events.Event{ID: "historical-v2", TenantID: "11111111-1111-4111-8111-111111111111", Type: EventEndpointVerified, SchemaVersion: endpointVerificationAlertEventSchemaVersionV2, Data: oldWire})
	if err != nil {
		t.Fatalf("schema-two evidence rejected after upgrade: %v", err)
	}
	_, superseded, err := decodeEndpointVerificationObservedWithDecision(old)
	if err != nil || superseded {
		t.Fatalf("historical alert decision changed: superseded=%v error=%v", superseded, err)
	}
	observed.AlertRequired, observed.SupersededExpectation = false, true
	newWire, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	newEvent, err := log.Append(t.Context(), events.Event{ID: "superseded-v3", TenantID: old.TenantID, Type: EventEndpointVerified, SchemaVersion: EndpointVerificationAlertEventSchemaVersion, Data: newWire})
	if err != nil {
		t.Fatalf("signed superseded evidence rejected: %v", err)
	}
	_, superseded, err = decodeEndpointVerificationObservedWithDecision(newEvent)
	if err != nil || !superseded {
		t.Fatalf("superseded decision lost on replay: superseded=%v error=%v", superseded, err)
	}
}
