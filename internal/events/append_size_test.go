// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestOversizedEventIsRejectedBeforeImmutableAppend(t *testing.T) {
	log, err := openFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	before, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(`{"data":"`), bytes.Repeat([]byte("x"), MaxEventDataBytes)...)
	payload = append(payload, []byte(`"}`)...)
	_, err = log.Append(t.Context(), Event{Type: "test.oversized", TenantID: "tenant-a", Data: payload})
	if !errors.Is(err, ErrEventPayloadTooLarge) {
		t.Fatalf("oversized append error = %v", err)
	}
	after, err := log.LastSequence(t.Context())
	if err != nil || after != before {
		t.Fatalf("oversized append changed log head: before=%d after=%d err=%v", before, after, err)
	}
}

func TestEncodedEventLimitRejectsBeforeIngressOrBrokerPublish(t *testing.T) {
	log, err := openFixture(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	before, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(`{"data":"`), bytes.Repeat([]byte("x"), 800000)...)
	payload = append(payload, []byte(`"}`)...)
	event := Event{ID: NewID(), Type: "test.encoded.oversized", TenantID: "tenant-a",
		Time: time.Now().UTC().Truncate(time.Microsecond), SchemaVersion: DefaultSchemaVersion, Data: payload}
	if err := log.PreflightAppendCapacity(event); !errors.Is(err, ErrEventWireTooLarge) {
		t.Fatalf("producer preflight error = %v, want encoded size refusal", err)
	}
	if _, err := log.Append(t.Context(), event); !errors.Is(err, ErrEventWireTooLarge) {
		t.Fatalf("encoded append error = %v, want size refusal", err)
	}
	after, err := log.LastSequence(t.Context())
	if err != nil || after != before {
		t.Fatalf("encoded refusal changed log head: before=%d after=%d err=%v", before, after, err)
	}
}
