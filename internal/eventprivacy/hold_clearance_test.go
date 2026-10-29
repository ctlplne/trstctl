// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/eventspec"
)

func holdClearanceFixture(t testing.TB) eventspec.Event {
	t.Helper()
	at := time.Now().UTC()
	request := eventprotect.DestructionRequest{Ref: eventprotect.KeyRef{TenantID: controlTestTenant, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}, OperationID: "eb08db3a-2d9e-4192-b2b9-b156308860e4", RegistrationIdentity: "opaque-registration", ActivationEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", ActivationSequence: 7, CreationDigest: strings.Repeat("a", 64), OffboardEventID: "opaque-offboard", OffboardSequence: 9, OffboardedAt: at, NotBefore: at.Add(time.Hour)}
	wire, err := json.Marshal(HoldClearance{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return eventspec.Event{ID: HoldClearanceEventID(request), Type: EventHoldClearance, TenantID: controlTestTenant, SchemaVersion: 1, Time: at, Sequence: 10, Data: wire}
}

func FuzzHoldClearance(f *testing.F) {
	seed := holdClearanceFixture(f)
	f.Add(seed.Data)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"request":null,"reason":"person@example.invalid"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		event := holdClearanceFixture(t)
		event.Data = data
		body, err := ParseHoldClearance(event)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(body)
		if err != nil || !bytes.Equal(canonical, data) || body.Request.Validate() != nil || body.Request.Ref.TenantID != event.TenantID || HoldClearanceEventID(body.Request) != event.ID {
			t.Fatal("noncanonical or cross-scope clearance entered parser authority")
		}
	})
}

func TestHoldClearanceWireIsClosedNonPersonalAndExact(t *testing.T) {
	event := holdClearanceFixture(t)
	if _, err := ParseHoldClearance(event); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*eventspec.Event){
		"tenant":       func(e *eventspec.Event) { e.TenantID = "22222222-2222-2222-2222-222222222222" },
		"identity":     func(e *eventspec.Event) { e.ID = "different" },
		"sequence":     func(e *eventspec.Event) { e.Sequence = 9 },
		"schema":       func(e *eventspec.Event) { e.SchemaVersion = 999 },
		"actor":        func(e *eventspec.Event) { e.Actor = &eventspec.Actor{Subject: "person@example.invalid"} },
		"erased-input": func(e *eventspec.Event) { e.SensitiveErased = true },
		"unknown-field": func(e *eventspec.Event) {
			e.Data = append(append([]byte(nil), e.Data[:len(e.Data)-1]...), []byte(`,"reason":"person@example.invalid"}`)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			mutate(&changed)
			if _, err := ParseHoldClearance(changed); !errors.Is(err, ErrSource) {
				t.Fatalf("changed clearance frame accepted: %v", err)
			}
		})
	}
}
