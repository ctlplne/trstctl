// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestExactEventRecoveryRefusesConflictingRetainedIdentity(t *testing.T) {
	ctx := context.Background()
	const dedupe = 100 * time.Millisecond
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithDuplicateWindowForTesting(dedupe))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	first := events.Event{
		ID: "recovered-command", Type: "test.recovery", TenantID: "11111111-1111-1111-1111-111111111111",
		Time: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), Data: []byte(`{"command":"first"}`),
	}
	if _, err := log.Append(ctx, first); err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []struct {
		name string
		fn   func(context.Context, string) (events.Event, bool, error)
	}{
		{name: "privacy erasure", fn: (&Orchestrator{log: log}).findPrivacyErasureEvent},
		{name: "lifecycle approval", fn: func(ctx context.Context, id string) (events.Event, bool, error) {
			return lifecycleApprovalEventByID(ctx, log, id)
		}},
	} {
		t.Run(lookup.name, func(t *testing.T) {
			if got, found, err := lookup.fn(ctx, first.ID); err != nil || !found || got.Sequence != 1 {
				t.Fatalf("canonical lookup = %+v, %t, %v", got, found, err)
			}
			if got, found, err := lookup.fn(ctx, "absent-command"); err != nil || found || got.ID != "" {
				t.Fatalf("absent lookup = %+v, %t, %v", got, found, err)
			}
		})
	}
	time.Sleep(4 * dedupe)
	second := first
	second.Data = []byte(`{"command":"conflicting"}`)
	if _, err := log.Append(ctx, second); err != nil {
		t.Fatal(err)
	}
	for _, lookup := range []struct {
		name string
		fn   func(context.Context, string) (events.Event, bool, error)
	}{
		{name: "privacy erasure", fn: (&Orchestrator{log: log}).findPrivacyErasureEvent},
		{name: "lifecycle approval", fn: func(ctx context.Context, id string) (events.Event, bool, error) {
			return lifecycleApprovalEventByID(ctx, log, id)
		}},
	} {
		t.Run(lookup.name+" conflict", func(t *testing.T) {
			got, found, err := lookup.fn(ctx, first.ID)
			if !errors.Is(err, events.ErrConflictingEventIdentity) || found || got.ID != "" {
				t.Fatalf("conflicting identity returned a command: %+v, %t, %v", got, found, err)
			}
		})
	}
}
