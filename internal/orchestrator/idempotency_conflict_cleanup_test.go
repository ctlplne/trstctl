// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestDurableBoundReceiverConflictReleasesOnlyFreshCacheClaim(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func(*testing.T) *orchestrator.Idempotency
	}{
		{
			name: "memory",
			new: func(*testing.T) *orchestrator.Idempotency {
				return orchestrator.NewMemoryIdempotency()
			},
		},
		{
			name: "postgres",
			new: func(t *testing.T) *orchestrator.Idempotency {
				return orchestrator.NewIdempotency(newStore(t))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idem := tc.new(t)
			ctx := context.Background()
			const (
				tenantID        = "11111111-1111-1111-1111-111111111111"
				key             = "privacy-erasure-after-generic-cache-gc"
				changedBinding  = "sha256:changed-command"
				originalBinding = "sha256:canonical-command"
			)

			result, err := idem.DoDurableEffectBound(
				ctx, tenantID, key, changedBinding,
				func(context.Context) ([]byte, error) {
					return nil, orchestrator.ErrIdempotencyConflict
				},
			)
			if !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(result) != 0 {
				t.Fatalf("changed receiver result=%q err=%v, want empty conflict", result, err)
			}

			calls := 0
			result, err = idem.DoDurableEffectBound(
				ctx, tenantID, key, originalBinding,
				func(context.Context) ([]byte, error) {
					calls++
					return []byte("canonical-response"), nil
				},
			)
			if err != nil {
				t.Fatalf("canonical recovery after receiver conflict: %v", err)
			}
			if string(result) != "canonical-response" || calls != 1 {
				t.Fatalf("canonical result=%q calls=%d, want canonical-response/1", result, calls)
			}

			replay, err := idem.DoDurableEffectBound(
				ctx, tenantID, key, originalBinding,
				func(context.Context) ([]byte, error) {
					t.Fatal("canonical replay executed callback")
					return nil, nil
				},
			)
			if err != nil || string(replay) != "canonical-response" {
				t.Fatalf("canonical replay=%q err=%v", replay, err)
			}
		})
	}
}
