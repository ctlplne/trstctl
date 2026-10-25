// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24: the older PQC reissue builds its CSR from a key
// the control plane generates, so the tenant's switch governs it. While the
// switch is off the job is refused before any key exists, as a definite
// no-effect the outbox retries; while it is on, the reissue records that the
// control plane generated the key and states that custody to the issuer.
func TestLegacyPQCReissueObeysTheControlPlaneKeygenSwitch(t *testing.T) {
	intent, _ := certificateProgressFixture(t)
	message := orchestrator.Message{TenantID: sealedTestTenant, Destination: licensedCryptoMigrationReissueDestination,
		IdempotencyKey: "licensed-crypto-migration:" + intent.RunID + ":" + intent.AssetID, Payload: mustJSON(t, intent)}
	errStop := errors.New("stop after the issuer call")
	var issued []custody.KeyOrigin
	var recorded []string
	allowed := false
	h := &outboxHandler{store: &store.Store{}, log: &events.Log{},
		idempotencyDo: func(ctx context.Context, _, _ string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
			return fn(ctx)
		},
		keygenAllowed: func(context.Context, string) (bool, error) { return allowed, nil },
		issue: func(_ context.Context, _, _, _ string, _ []byte, origin custody.KeyOrigin) ([]byte, error) {
			issued = append(issued, origin)
			return nil, errStop
		},
		appendEvent: func(_ context.Context, _, eventType string, _ any) error {
			recorded = append(recorded, eventType)
			return nil
		},
	}
	err := h.handlePQCReissue(context.Background(), message)
	if !errors.Is(err, orchestrator.ErrControlPlaneKeygenOff) || !orchestrator.IsDefiniteNoEffect(err) ||
		len(issued) != 0 || len(recorded) != 0 {
		t.Fatalf("reissue while off = %v (issued %v, recorded %v), want a definite no-effect refusal before any key", err, issued, recorded)
	}
	allowed = true
	if err := h.handlePQCReissue(context.Background(), message); !errors.Is(err, errStop) {
		t.Fatalf("reissue while on = %v, want it to reach the issuer", err)
	}
	if len(issued) != 1 || issued[0] != custody.OriginControlPlane {
		t.Fatalf("issuer custody = %v, want control_plane", issued)
	}
	if len(recorded) != 1 || recorded[0] != "issuance.server_side_keygen" {
		t.Fatalf("recorded = %v, want the key generation recorded", recorded)
	}
}
