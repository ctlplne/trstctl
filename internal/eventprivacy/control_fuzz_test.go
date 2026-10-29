// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/eventspec"
)

func FuzzActivatedControl(f *testing.F) {
	request, err := NewRequested(controlTestTenant, "fuzz-registration", time.Second)
	if err != nil {
		f.Fatal(err)
	}
	base := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	// This is a wire-shape seed only. A production activation additionally
	// requires exact source parents and independent cryptographic key readback.
	activation := Activated{RegistrationIdentity: request.RegistrationIdentity, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: RequestedEventID(request), RequestedSequence: 1, RequestedAt: base, Creation: eventprotect.KeyCreationEvidence{Version: 2, Ref: eventprotect.KeyRef{TenantID: controlTestTenant, ID: request.KeyID}, CreatedAt: base.Add(time.Second), Probe: []byte("public-probe-shape-only")}}
	wire, err := json.Marshal(activation)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire, false, false)
	f.Add(wire, true, false)
	f.Add(wire, false, true)
	f.Add([]byte(`null`), false, false)
	f.Fuzz(func(t *testing.T, input []byte, privateActor, encrypted bool) {
		event := eventspec.Event{ID: request.KeyID, Type: EventActivated, TenantID: controlTestTenant, Time: base.Add(time.Second), SchemaVersion: 1, Sequence: 2, Data: input}
		if privateActor {
			event.Actor = &eventspec.Actor{Subject: "private actor"}
		}
		if encrypted {
			event.Protection = &eventspec.ProtectedPayload{}
		}
		got, err := ParseActivated(event)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(got)
		expected, bindingErr := NewRequested(controlTestTenant, got.RegistrationIdentity, time.Duration(got.RetentionNanos))
		if privateActor || encrypted || err != nil || bindingErr != nil || !bytes.Equal(canonical, input) || got.Requested() != expected || got.Creation.Ref.TenantID != controlTestTenant {
			t.Fatal("accepted ambiguous, private or unbound activation")
		}
	})
}

func FuzzDestroyedControl(f *testing.F) {
	f.Add([]byte(`{"jws":"fixture"}`), false, false)
	f.Add([]byte(`{"jws":"fixture"}`), true, false)
	f.Add([]byte(`{"jws":"fixture"}`), false, true)
	f.Add([]byte(`null`), false, false)
	f.Fuzz(func(t *testing.T, input []byte, privateActor, encrypted bool) {
		event := eventspec.Event{Type: EventDestroyed, SchemaVersion: 1, Data: input}
		if privateActor {
			event.Actor = &eventspec.Actor{Subject: "private actor"}
		}
		if encrypted {
			event.Protection = &eventspec.ProtectedPayload{}
		}
		got, err := ParseDestroyed(event)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(got)
		if privateActor || encrypted || err != nil || !bytes.Equal(canonical, input) || len(got.JWS) == 0 || len(got.JWS) > 12<<10 {
			t.Fatal("accepted ambiguous/private completion")
		}
	})
}
