// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type existingEffectOutboxHandler struct {
	idem          *orchestrator.Idempotency
	calls         map[string]int
	terminalCalls int
}

func (h *existingEffectOutboxHandler) Deliver(ctx context.Context, m orchestrator.Message) error {
	_, err := h.idem.DoAtMostOnceEffect(ctx, m.TenantID, "existing-effect:"+m.IdempotencyKey, func(context.Context) ([]byte, error) {
		h.calls[m.IdempotencyKey]++
		if m.IdempotencyKey == "ambiguous" {
			return nil, errors.New("controlled lost provider response")
		}
		return []byte("recorded result"), nil
	})
	if err != nil {
		return fmt.Errorf("external CA delivery: %w", err)
	}
	return nil
}
func (h *existingEffectOutboxHandler) DeliverTerminalFailure(context.Context, orchestrator.Message, error) error {
	h.terminalCalls++
	return nil
}

func TestExistingAtMostOnceFenceDoesNotFailAuthorityProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold int
		memory    bool
	}{
		{"postgres-half-open", 1, false}, {"postgres-closed", 3, false},
		{"memory-half-open", 1, true}, {"memory-closed", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			mustRegisterTenant(t, s, tenantA)
			now := time.Now().UTC()
			ob := orchestrator.NewOutbox(s, orchestrator.WithNow(func() time.Time { return now }),
				orchestrator.WithBackoff(func(int) time.Duration { return time.Second }),
				orchestrator.WithRetryJitter(func(d time.Duration) time.Duration { return d }),
				orchestrator.WithCircuitBreaker(tc.threshold, time.Minute), orchestrator.WithMaxAttempts(3))
			badID := enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "external-ca.issue", EffectLane: "external-ca.issue:authority:existing", IdempotencyKey: "ambiguous", Payload: []byte(`{}`)})
			now = now.Add(time.Second) // Include the database-created intent timestamps in the test clock cut.
			idem := orchestrator.NewIdempotency(s)
			if tc.memory {
				idem = orchestrator.NewMemoryIdempotency()
			}
			h := &existingEffectOutboxHandler{idem: idem, calls: make(map[string]int)}
			expectedState := orchestrator.CircuitClosed
			if tc.threshold == 1 {
				expectedState = orchestrator.CircuitOpen
			}
			scope := orchestrator.DestinationScope{IncludePrefixes: []string{"external-ca.issue"}}
			if claimed, err := ob.DispatchOneScoped(t.Context(), h, scope); err != nil || !claimed {
				t.Fatalf("first attempt: %v %v", claimed, err)
			}
			circuits := ob.CircuitStates()
			if len(circuits) != 1 || circuits[0].State != expectedState || circuits[0].Failures != 1 {
				t.Fatalf("real ambiguous call must affect health: %+v", circuits)
			}
			now = now.Add(time.Minute + time.Second)
			if claimed, err := ob.DispatchOneScoped(t.Context(), h, scope); err != nil || !claimed {
				t.Fatalf("local fence attempt: %v %v", claimed, err)
			}
			if h.calls["ambiguous"] != 1 {
				t.Fatal("local fence re-entered the provider")
			}
			assertOriginalReceiverHold := func() {
				t.Helper()
				if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
					var pending int
					if err := tx.QueryRow(t.Context(), `SELECT cardinality(receiver_pending_ids)
						FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, badID).Scan(&pending); err != nil {
						return err
					}
					if pending != 1 {
						t.Errorf("local authority probe invented remote work: pending=%d, want only the original uncertain invocation", pending)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.WithTenantServiceBarrier(t.Context(), tenantA, func(ctx context.Context) error {
					_, err := s.OffboardTenant(ctx, tenantA)
					return err
				}); !errors.Is(err, store.ErrTenantServiceBusy) {
					t.Fatalf("local refusal erased original uncertainty: %v", err)
				}
			}
			assertOriginalReceiverHold()
			bad, err := ob.Get(t.Context(), tenantA, badID)
			if err != nil || bad.Attempts != 2 {
				t.Fatalf("expected second attempt of uncertain command: %+v %v", bad, err)
			}
			circuits = ob.CircuitStates()
			if len(circuits) != 1 || circuits[0].State != expectedState || circuits[0].Failures != 1 || circuits[0].OpenUntil.After(now) {
				t.Fatalf("local refusal changed health or retained probe reservation: %+v", circuits)
			}
			// A local refusal must release a half-open probe without claiming success.
			// The other command must be allowed to make the actual next provider probe.
			goodID := enqueue(t, s, ob, orchestrator.Entry{TenantID: tenantA, Destination: "external-ca.issue", EffectLane: "external-ca.issue:authority:existing", IdempotencyKey: "healthy", Payload: []byte(`{}`)})
			if claimed, err := ob.DispatchOneScoped(t.Context(), h, scope); err != nil || !claimed {
				t.Fatalf("local fence blocked a healthy authority command: %v %v circuits=%+v", claimed, err, ob.CircuitStates())
			}
			good, err := ob.Get(t.Context(), tenantA, goodID)
			if err != nil || good.Status != "delivered" || h.calls["healthy"] != 1 {
				t.Fatalf("healthy command: %+v calls=%v error=%v", good, h.calls, err)
			}
			// Local refusals still consume the ordinary retry budget and run the
			// existing terminal callback. They do not erase the uncertain claim.
			now = now.Add(2 * time.Second)
			if claimed, err := ob.DispatchOneScoped(t.Context(), h, scope); err != nil || !claimed {
				t.Fatalf("terminal local attempt: %v %v", claimed, err)
			}
			bad, err = ob.Get(t.Context(), tenantA, badID)
			if err != nil || bad.Status != "failed" || bad.Attempts != 3 || h.terminalCalls != 1 || h.calls["ambiguous"] != 1 {
				t.Fatalf("terminal local refusal: %+v calls=%v terminal=%d error=%v", bad, h.calls, h.terminalCalls, err)
			}
			assertOriginalReceiverHold()
			if _, err := h.idem.DoAtMostOnceEffect(t.Context(), tenantA, "existing-effect:ambiguous", func(context.Context) ([]byte, error) { t.Fatal("uncertain claim was reopened"); return nil, nil }); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
				t.Fatalf("uncertain claim lost: %v", err)
			}
		})
	}
}
