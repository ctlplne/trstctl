// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventspec"
)

func FuzzProtectedStoredEnvelope(f *testing.F) {
	seed, err := json.Marshal(storedEvent{
		ID: "fuzz-source", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c",
		Time: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), SchemaVersion: protectedWireSchemaVersion,
		PayloadSchemaVersion: 1, Data: protectedWireMarker,
		Protection: &eventspec.ProtectedPayload{Version: 1, KeyID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", PolicyDigest: strings.Repeat("a", 64), Ciphertext: []byte("opaque-ciphertext")},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(append([]byte(`{"id":"shadow",`), seed[1:]...))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 1<<20 {
			t.Skip("outside this bounded envelope fuzz corpus")
		}
		event, err := decodeStored(wire, 1)
		if err != nil || event.Protection == nil {
			return
		}
		stored, err := storedForEvent(event)
		if err != nil {
			t.Fatal("decoded protected source could not retain its framing")
		}
		canonical, err := json.Marshal(stored)
		if err != nil || !bytes.Equal(canonical, wire) || event.Actor != nil || !bytes.Equal(event.Data, protectedWireMarker) {
			t.Fatal("protected source accepted an ambiguous or readable wire encoding")
		}
	})
}
