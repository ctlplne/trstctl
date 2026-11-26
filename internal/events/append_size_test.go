// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"errors"
	"testing"

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
