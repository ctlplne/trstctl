// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestHalfOpenProbeReleasesAfterCancelledFinalizationOrDeferral(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled-finalization", true: "no-effect-deferral"}[deferred], func(t *testing.T) {
			s := newStore(t)
			mustRegisterTenant(t, s, tenantA)
			now := time.Now().UTC().Add(time.Hour)
			ob := orchestrator.NewOutbox(s,
				orchestrator.WithNow(func() time.Time { return now }),
				orchestrator.WithBackoff(func(int) time.Duration { return time.Second }),
				orchestrator.WithRetryJitter(func(d time.Duration) time.Duration { return d }),
				orchestrator.WithLeaseTTL(time.Minute),
				orchestrator.WithCircuitBreaker(1, time.Minute))
			id := enqueue(t, s, ob, orchestrator.Entry{
				TenantID: tenantA, Destination: "external-ca.issue", EffectLane: "external-ca.issue:authority:probe-release",
				IdempotencyKey: "same-durable-command", Payload: []byte(`{}`),
			})
			scope := orchestrator.DestinationScope{IncludePrefixes: []string{"external-ca.issue"}}
			if claimed, err := ob.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
				return errors.New("controlled local recording failure")
			}), scope); err != nil || !claimed {
				t.Fatalf("initial failed delivery: claimed=%v error=%v", claimed, err)
			}
			now = now.Add(2 * time.Minute)
			probeCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			claimed, err := ob.DispatchOneScoped(probeCtx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
				states := ob.CircuitStates()
				if len(states) != 1 || states[0].State != orchestrator.CircuitHalfOpen {
					t.Fatalf("probe did not reserve the failing authority: %+v", states)
				}
				if deferred {
					return orchestrator.DeferDelivery(errors.New("receiver effect was not started"))
				}
				cancel() // The handler returns, but SQL finalization cannot use this context.
				return context.Canceled
			}), scope)
			if !claimed || (!deferred && !errors.Is(err, context.Canceled)) || (deferred && err != nil) {
				t.Fatalf("probe result: claimed=%v error=%v deferred=%v", claimed, err, deferred)
			}
			states := ob.CircuitStates()
			if len(states) != 1 || states[0].State != orchestrator.CircuitOpen || states[0].Failures != 1 || states[0].OpenUntil.After(now) {
				t.Fatalf("finished local probe retained reservation or changed authority health: %+v", states)
			}
			if !deferred {
				if claimed, err := ob.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
					t.Fatal("released circuit bypassed the still-live durable lease")
					return nil
				}), scope); err != nil || claimed {
					t.Fatalf("live lease should retain delivery ownership: claimed=%v error=%v", claimed, err)
				}
			}
			now = now.Add(2 * time.Minute)
			calls := 0
			if claimed, err := ob.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
				calls++
				if m.ID != id || m.IdempotencyKey != "same-durable-command" {
					t.Fatal("recovery changed the durable command")
				}
				return nil
			}), scope); err != nil || !claimed || calls != 1 {
				t.Fatalf("same-process lease recovery blocked: claimed=%v calls=%d error=%v", claimed, calls, err)
			}
			record, err := ob.Get(t.Context(), tenantA, id)
			wantAttempts := 3
			if deferred {
				wantAttempts = 2
			}
			if err != nil || record.Status != "delivered" || record.Attempts != wantAttempts {
				t.Fatalf("recovery changed delivery accounting: %+v error=%v", record, err)
			}
			states = ob.CircuitStates()
			if len(states) != 1 || states[0].State != orchestrator.CircuitClosed || states[0].Failures != 0 {
				t.Fatalf("successful retry did not close the circuit: %+v", states)
			}
		})
	}
}
