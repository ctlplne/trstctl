// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestPQCCertificateTerminalFailureStopsQueuedWorkAndRedactsReceiverErrors(t *testing.T) {
	for _, operation := range []string{"issue", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			intent, log := certificateProgressFixture(t)
			p := NewProgressProjection(nil)
			applyProgressLog(t, p, log[:1])
			message := orchestrator.Message{TenantID: sealedTestTenant, Destination: licensedCryptoMigrationReissueDestination,
				IdempotencyKey: "licensed-crypto-migration:" + intent.RunID + ":" + intent.AssetID, Payload: mustJSON(t, intent)}
			wantStatus := TLSFindingFailed
			if operation == "rollback" {
				message.Destination = licensedCryptoMigrationRollbackDestination
				message.IdempotencyKey = "licensed-crypto-migration-rollback:" + intent.RunID + ":" + intent.AssetID
				message.Payload = mustJSON(t, pqcMigrationRollbackPayload{RunID: intent.RunID, Reason: "operator reason must not leak", Restore: projections.LicensedCryptoMigrationRollbackCompleted{RunID: intent.RunID, AssetID: intent.AssetID}})
				wantStatus = TLSFindingRollbackFailed
			}
			var body []byte
			h := &outboxHandler{appendEvent: func(ctx context.Context, tenant, eventType string, payload any) error {
				if eventType != EventCertificateFindingFailed || tenant != sealedTestTenant {
					t.Fatalf("unexpected failure event %s tenant %s", eventType, tenant)
				}
				var err error
				body, err = json.Marshal(payload)
				if err != nil {
					return err
				}
				return p.Apply(ctx, events.Event{Type: eventType, TenantID: tenant, SchemaVersion: 1, Data: body})
			}}
			if handled, err := h.DeliverLicensedTerminalFailure(context.Background(), message, errors.New("receiver password=fake-secret; private-host.example")); !handled || err != nil {
				t.Fatalf("handled=%v err=%v", handled, err)
			}
			for _, forbidden := range []string{"fake-secret", "private-host.example", "operator reason", "api.example.test"} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Fatalf("failure disclosed %q", forbidden)
				}
			}
			got := p.Snapshot(sealedTestTenant, intent.RunID)
			if len(got) != 1 || got[0].Status != wantStatus || got[0].Failure == "" {
				t.Fatalf("failure left work queued or invisible: %+v", got)
			}
			if len(p.Snapshot("22222222-2222-4222-8222-222222222222", intent.RunID)) != 0 {
				t.Fatal("failure crossed tenant boundary")
			}
			response := progressResponse(intent.RunID, got)
			if response.Total != 1 || response.Failed != 1 || response.Queued != 0 {
				t.Fatalf("failure missing from API counts: %+v", response)
			}
		})
	}
}

func TestPQCCertificateTerminalFailureRejectsMismatchedOutboxBinding(t *testing.T) {
	intent, _ := certificateProgressFixture(t)
	called := false
	h := &outboxHandler{appendEvent: func(context.Context, string, string, any) error { called = true; return nil }}
	message := orchestrator.Message{TenantID: sealedTestTenant, Destination: licensedCryptoMigrationReissueDestination, IdempotencyKey: "other-run", Payload: mustJSON(t, intent)}
	if handled, err := h.DeliverLicensedTerminalFailure(context.Background(), message, nil); !handled || err == nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if called {
		t.Fatal("mismatched payload changed progress")
	}
}
