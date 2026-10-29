// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventspec"
)

// FuzzProtectedPayloadFrame checks the authenticated inner frame directly, so
// mutations reach its length/actor parser instead of stopping at an AEAD tag.
func FuzzProtectedPayloadFrame(f *testing.F) {
	for _, payload := range []Payload{
		{}, {Data: []byte(`{"reason":"synthetic marker"}`)},
		{Data: []byte("\n\t exact opaque bytes \x00"), Actor: &eventspec.Actor{Subject: "synthetic actor", Roles: []string{"reader"}}},
	} {
		frame, err := encodePayload(payload)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame)
	}
	f.Add([]byte(nil))
	f.Add([]byte("EPF1"))
	f.Add([]byte("EPF1\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > maxCipherBytes {
			t.Skip("outside the bounded source transport")
		}
		payload, err := decodePayload(frame)
		if err != nil {
			return
		}
		defer secret.Wipe(payload.Data)
		reencoded, err := encodePayload(payload)
		defer secret.Wipe(reencoded)
		if err != nil || !bytes.Equal(frame, reencoded) {
			t.Fatal("accepted frame was not one canonical, lossless encoding")
		}
	})
}

// Exercise the signed receipt's canonical claims parser directly so mutations
// reach its interpretation rules rather than stopping at the JWS signature.
func FuzzDestructionClaims(f *testing.F) {
	at := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	claims := DestructionClaims{
		Schema: destructionReceiptSchema,
		Request: DestructionRequest{
			Ref:         KeyRef{TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
			OperationID: "93ba00d2-9108-4f7f-8c9d-f6e887ba0612", OffboardEventID: "fixture-offboard", OffboardSequence: 9,
			RegistrationIdentity: "fixture-registration", ActivationEventID: "fixture-activation", ActivationSequence: 5,
			CreationDigest: strings.Repeat("a", 64),
			OffboardedAt:   at, NotBefore: at.Add(time.Hour),
		},
		RemovedAt: at.Add(time.Hour),
	}
	seed, err := json.Marshal(claims)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema":"ignored",` + string(seed[1:])))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		got, err := decodeDestructionClaims(wire)
		if err != nil {
			return
		}
		reencoded, err := json.Marshal(got)
		if err != nil || !bytes.Equal(wire, reencoded) || validateDestructionRequest(got.Request) != nil || got.RemovedAt.Before(got.Request.NotBefore) {
			t.Fatal("accepted claims were ambiguous or lacked retention authority")
		}
	})
}
