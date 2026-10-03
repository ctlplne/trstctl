// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestFirstDynamicSecretRevocationCompletionHasNoRetryAttempt(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tt := range []struct {
		name      string
		attemptID string
	}{
		{name: "initial retirement"},
		{name: "retry retirement", attemptID: "retry-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(DynamicSecretLeaseRevocationCompleted{
				TenantEpoch: "epoch-1", ID: "lease-1", AttemptID: tt.attemptID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(ctx, events.Event{TenantID: "33333333-3333-4333-8333-333333333333", Type: EventDynamicSecretLeaseRevocationCompleted, SchemaVersion: DynamicSecretEventSchemaVersion, Data: payload}); err != nil {
				t.Fatalf("closed event privacy policy rejected valid completion: %v", err)
			}
			failure, err := json.Marshal(DynamicSecretLeaseFailure{
				TenantEpoch: "epoch-1", ID: "lease-1", Error: "provider denied", AttemptID: tt.attemptID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(ctx, events.Event{TenantID: "33333333-3333-4333-8333-333333333333", Type: EventDynamicSecretLeaseRevocationFailed, SchemaVersion: DynamicSecretEventSchemaVersion, Data: failure}); err != nil {
				t.Fatalf("closed event privacy policy rejected valid failure: %v", err)
			}
		})
	}
	if _, err := log.Append(ctx, events.Event{TenantID: "33333333-3333-4333-8333-333333333333", Type: EventDynamicSecretLeaseRevocationCompleted, SchemaVersion: DynamicSecretEventSchemaVersion, Data: []byte(`{"tenant_epoch":"epoch-1","id":"lease-1","unexpected":"secret"}`)}); err == nil {
		t.Fatal("closed event privacy policy accepted an undeclared field")
	}
}
