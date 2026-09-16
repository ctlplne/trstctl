// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestFailedEndpointVerificationPersistsWithoutInventedValidity(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	observed := EndpointVerificationObserved{EndpointID: "expired-postgresql", Address: "postgresql.example.test:5432", Vantage: "relay", Reached: false, Detail: "certificate has expired", ObservedAt: time.Now().UTC()}
	wire, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "expired-endpoint-proof", TenantID: "11111111-1111-4111-8111-111111111111", Type: EventEndpointVerified, SchemaVersion: 1, Data: wire}
	if _, err := log.Append(t.Context(), event); err != nil {
		t.Fatalf("failed verification disappeared instead of being recorded: %v", err)
	}
	found, ok, err := log.EventByID(t.Context(), event.ID)
	if err != nil || !ok {
		t.Fatalf("failed verification was not retained: found=%v error=%v", ok, err)
	}
	var restored EndpointVerificationObserved
	if err := json.Unmarshal(found.Data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Reached || !restored.NotBefore.IsZero() || !restored.NotAfter.IsZero() || restored.Detail != observed.Detail {
		t.Fatalf("failure evidence changed or invented validity: %+v", restored)
	}
	for _, bad := range []func(map[string]any){
		func(m map[string]any) { delete(m, "endpoint_id") },
		func(m map[string]any) { m["not_before"] = 42 },
		func(m map[string]any) { m["unregistered_subject"] = "unexpected" },
	} {
		var fields map[string]any
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		bad(fields)
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		event.ID += "-rejected"
		event.Data = data
		if _, err := log.Append(t.Context(), event); err == nil {
			t.Fatal("closed privacy shape accepted missing required data or undeclared fields")
		}
	}
}
