// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestDestructionControlGrantBindsWholeEventAndExpires(t *testing.T) {
	authority, foreign := NewDestructionAuthority(), NewDestructionAuthority()
	event := holdClearanceFixture(t)
	body, err := ParseHoldClearance(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Sequence = 0
	claim := DestructionClaim{ID: 17, AttemptID: "fdc5ca32-fb7d-4ea3-b640-fcf032cb0ac5", Attempts: 2, Command: body.Request}
	if _, err := authority.ControlClaim(t.Context(), event); !errors.Is(err, ErrSource) {
		t.Fatal("missing private grant admitted a control")
	}
	var escaped context.Context
	if err := authority.withControlGrant(t.Context(), claim, event, func(ctx context.Context) error {
		escaped = ctx
		got, err := authority.ControlClaim(ctx, event)
		if err != nil || got.ID != claim.ID || got.AttemptID != claim.AttemptID || got.Attempts != claim.Attempts || !sameDestructionRequest(got.Command, claim.Command) {
			t.Fatalf("exact claim changed: %v", err)
		}
		if _, err := foreign.ControlClaim(ctx, event); !errors.Is(err, ErrSource) {
			t.Fatal("another authority borrowed the control grant")
		}
		for name, mutate := range map[string]func(*events.Event){
			"id":       func(e *events.Event) { e.ID += "-changed" },
			"tenant":   func(e *events.Event) { e.TenantID = "22222222-2222-2222-2222-222222222222" },
			"type":     func(e *events.Event) { e.Type = EventDestroyed },
			"schema":   func(e *events.Event) { e.SchemaVersion++ },
			"sequence": func(e *events.Event) { e.Sequence++ },
			"time":     func(e *events.Event) { e.Time = e.Time.Add(time.Nanosecond) },
			"data":     func(e *events.Event) { e.Data = append(bytes.Clone(e.Data), ' ') },
			"actor":    func(e *events.Event) { e.Actor = &events.Actor{Subject: "fixture-private@example.invalid"} },
			"envelope": func(e *events.Event) { e.Protection = &eventspec.ProtectedPayload{Version: 1} },
			"erased":   func(e *events.Event) { e.SensitiveErased = true },
		} {
			t.Run(name, func(t *testing.T) {
				changed := event
				mutate(&changed)
				if _, err := authority.ControlClaim(ctx, changed); !errors.Is(err, ErrSource) {
					t.Fatalf("modified event admitted: %v", err)
				}
			})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ControlClaim(escaped, event); !errors.Is(err, ErrSource) {
		t.Fatal("control grant survived callback")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := authority.withControlGrant(ctx, claim, event, func(context.Context) error { t.Fatal("canceled context minted control grant"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
