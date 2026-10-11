// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestCACrossSignedEventHasClosedOnlineAndOfflinePrivacyShapes(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	base := map[string]any{
		"ca_id": "issuer-1", "ceremony_id": "ceremony-1",
		"target_certificate_der": "AQID", "cross_certificate_der": "BAUG",
		"target_sha256": "target-digest",
	}
	// Historic hierarchy events contain only these identities. Replaying them
	// must remain possible, while their absent certificate cannot create a
	// public readback receipt.
	legacy := events.Event{ID: "legacy-ca-cross-sign-privacy",
		TenantID: "11111111-1111-4111-8111-111111111111",
		Type:     EventCACrossSigned, SchemaVersion: 1,
		Data: []byte(`{"ca_id":"issuer-1","ceremony_id":"ceremony-1"}`)}
	if _, err := log.Append(t.Context(), legacy); err != nil {
		t.Fatalf("historic CA cross-sign shape was refused: %v", err)
	}
	for _, tc := range []struct {
		name    string
		offline bool
	}{
		{name: "online"},
		{name: "offline", offline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := make(map[string]any, len(base)+1)
			for key, value := range base {
				payload[key] = value
			}
			if tc.offline {
				payload["offline_root"] = true
			}
			wire, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			event := events.Event{ID: "ca-cross-sign-privacy-" + tc.name,
				TenantID: "11111111-1111-4111-8111-111111111111",
				Type:     EventCACrossSigned, SchemaVersion: 1, Data: wire}
			if _, err := log.Append(t.Context(), event); err != nil {
				t.Fatalf("valid %s CA cross-sign was refused: %v", tc.name, err)
			}
			found, ok, err := log.EventByID(t.Context(), event.ID)
			if err != nil || !ok || string(found.Data) != string(wire) {
				t.Fatalf("durable %s CA cross-sign changed: found=%v error=%v", tc.name, ok, err)
			}
			payload["undeclared_identity"] = "alice@example.test"
			bad, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			event.ID += "-invalid"
			event.Data = bad
			if _, err := log.Append(t.Context(), event); err == nil {
				t.Fatal("closed CA cross-sign privacy shape accepted an undeclared identity")
			}
		})
	}
}
