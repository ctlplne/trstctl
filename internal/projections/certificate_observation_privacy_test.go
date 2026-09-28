// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestCertificateObservationUsesClosedVersionedPayload(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	payload, err := json.Marshal(CertificateRecorded{ID: "import", Source: "issued", ObservationOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "old-observation", Type: EventCertificateRecorded, TenantID: "11111111-1111-4111-8111-111111111111", SchemaVersion: 1, Data: payload}
	if _, err := log.Append(t.Context(), event); err == nil {
		t.Fatal("new observation marker widened the historical version-one payload")
	}
	event.ID, event.SchemaVersion = "versioned-observation", CertificateObservationEventSchemaVersion
	if _, err := log.Append(t.Context(), event); err != nil {
		t.Fatalf("explicit observation payload rejected: %v", err)
	}
	retained, found, err := log.EventByID(t.Context(), event.ID)
	if err != nil || !found || !bytes.Equal(retained.Data, payload) {
		t.Fatalf("observation marker or operator source changed: found=%t error=%v", found, err)
	}
	event.ID, event.Data = "undeclared-observation", []byte(string(payload[:len(payload)-1])+`,"private_key":"undeclared"}`)
	if _, err := log.Append(t.Context(), event); err == nil {
		t.Fatal("observation payload accepted an undeclared field")
	}
	legacy, err := json.Marshal(CertificateRecorded{ID: "legacy", Source: "issued"})
	if err != nil {
		t.Fatal(err)
	}
	event.ID, event.Data = "missing-marker", legacy
	if _, err := log.Append(t.Context(), event); err == nil {
		t.Fatal("observation version accepted a missing marker")
	}
	event.ID, event.SchemaVersion = "original-version", 1
	if _, err := log.Append(t.Context(), event); err != nil {
		t.Fatalf("historical payload stopped working: %v", err)
	}
}
