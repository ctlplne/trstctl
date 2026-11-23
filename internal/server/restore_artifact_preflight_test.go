// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
)

func TestVerifiedRawHistoryPreflightRejectsUnknownSealedFieldCR045(t *testing.T) {
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, events.WithAppendAdmission(func(ctx context.Context, _ events.Event,
		publish func(context.Context) (events.Event, error),
	) (events.Event, error) {
		return publish(ctx)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(t.Context(), events.Event{
		Type: "fixture.unknown_sealed_event", TenantID: "60aad68e-4613-4658-a75a-10ee97084edf",
		Data: []byte(`{"sealed":"AQI="}`),
	}); err != nil {
		t.Fatal(err)
	}
	key := []byte("plain backup integrity fixture")
	var artifact bytes.Buffer
	if _, err := backup.WriteLogWithKey(t.Context(), log, &artifact, key); err != nil {
		t.Fatal(err)
	}
	if err := backup.WithVerifiedHistoryReader(t.Context(), bytes.NewReader(artifact.Bytes()), key,
		func(source *backup.VerifiedHistoryReader) error {
			return validateVerifiedRawHistory(t.Context(), source, nil, nil, nil)
		}); err == nil {
		t.Fatal("HMAC-verified unknown sealed field passed raw-history preflight")
	}
}

func TestVerifiedRawHistoryPreflightRejectsUnknownFieldInKnownSchemaCR045(t *testing.T) {
	if err := events.ValidateRegisteredEventPayload(events.Event{
		Type: "tenant.registered", SchemaVersion: events.DefaultSchemaVersion,
		Data: []byte(`{"name":"plain tenant"}`),
	}); err != nil {
		t.Fatalf("known registration schema control: %v", err)
	}
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	}, events.WithAppendAdmission(func(ctx context.Context, _ events.Event,
		publish func(context.Context) (events.Event, error),
	) (events.Event, error) {
		return publish(ctx)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(t.Context(), events.Event{
		Type: "tenant.registered", TenantID: "60aad68e-4613-4658-a75a-10ee97084edf",
		Data: []byte(`{"name":"plain tenant","opaque_payload":"AQI="}`),
	}); err != nil {
		t.Fatal(err)
	}
	key := []byte("plain backup integrity fixture")
	var artifact bytes.Buffer
	if _, err := backup.WriteLogWithKey(t.Context(), log, &artifact, key); err != nil {
		t.Fatal(err)
	}
	if err := backup.WithVerifiedHistoryReader(t.Context(), bytes.NewReader(artifact.Bytes()), key,
		func(source *backup.VerifiedHistoryReader) error {
			return validateVerifiedRawHistory(t.Context(), source, nil, nil, nil)
		}); err == nil {
		t.Fatal("unknown field in a known event schema passed raw-history preflight")
	}
}
