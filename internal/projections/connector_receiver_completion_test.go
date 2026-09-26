// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func connectorReceiverFixture(t *testing.T) (*store.Store, projections.ConnectorDeliveryRecorded, []string) {
	t.Helper()
	s := newStore(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Receiver recovery fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{uuid.NewString(), uuid.NewString()}
	var outboxID int64
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox
			(tenant_id,destination,payload,idempotency_key,status,attempts,next_attempt_at,receiver_pending_ids)
			VALUES ($1,'connector.deploy','{}','receiver-fixture','pending',2,now(),$2::uuid[]) RETURNING id`, tenantA, ids).Scan(&outboxID)
	}); err != nil {
		t.Fatal(err)
	}
	return s, projections.ConnectorDeliveryRecorded{
		ID: uuid.NewString(), OutboxID: &outboxID, Destination: "connector.deploy",
		Connector: "receiver-fixture", Target: "owned-target", Fingerprint: "sha256:fixture",
		Status: "delivered", Attempts: 2, IdempotencyKey: "receiver-fixture", ReceiverAttemptID: ids[0],
	}, ids
}

func receiverPendingIDs(t *testing.T, s *store.Store, outboxID int64) []string {
	t.Helper()
	var ids []string
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT receiver_pending_ids::text[] FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, outboxID).Scan(&ids)
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestConnectorReceiverCompletionRecoversRetainedEventAtomically(t *testing.T) {
	s, receipt, ids := connectorReceiverFixture(t)
	ctx := t.Context()
	log := openLog(t)
	event, err := log.Append(ctx, connectorReceiverEvent(t, tenantA, receipt))
	if err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("controlled interruption before projection commit")
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := projections.New(s).ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		return interrupted
	})
	if !errors.Is(err, interrupted) {
		t.Fatalf("interrupted projection: %v", err)
	}
	if got := receiverPendingIDs(t, s, *receipt.OutboxID); !reflect.DeepEqual(got, ids) {
		t.Fatalf("rollback changed receiver holds: %v", got)
	}
	if _, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("rolled-back receipt persisted: %v", err)
	}
	// A new projector consumes the durable event, as recovery does. Repeating
	// it is harmless and cannot clear the unrelated, still-unknown invocation.
	for range 2 {
		if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
			t.Fatal(err)
		}
		if err := projections.New(s).Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if got := receiverPendingIDs(t, s, *receipt.OutboxID); !reflect.DeepEqual(got, ids[1:]) {
		t.Fatalf("replay cleared the wrong receiver holds: %v", got)
	}
	if err := s.RequireTenantAgentWorkQuiescent(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("unknown earlier call did not block lifecycle: %v", err)
	}
	// Only another terminal receipt naming that invocation releases its hold.
	receipt.ReceiverAttemptID = ids[1]
	second, err := log.Append(ctx, connectorReceiverEvent(t, tenantA, receipt))
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenantServiceBarrier(ctx, tenantA, func(work context.Context) error {
		return s.RequireTenantAgentWorkQuiescent(work, tenantA)
	}); err != nil {
		t.Fatalf("terminal receipts still block lifecycle: %v", err)
	}
	// Outbox retention must not make old terminal history unreplayable or
	// recreate a command. Receiver holds have already been reconciled.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND id=$2`, tenantA, *receipt.OutboxID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, event); err != nil {
		t.Fatalf("replay after retention: %v", err)
	}
}

func TestConnectorReceiverCompletionRequiresExactEvidence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		change        func(*projections.ConnectorDeliveryRecorded)
		foreignTenant bool
		wantError     bool
		version       int
	}{
		{name: "v1-cannot-carry-completion", version: 1, wantError: true},
		{name: "v2-requires-completion", version: 2, change: func(r *projections.ConnectorDeliveryRecorded) { r.ReceiverAttemptID = "" }, wantError: true},
		{name: "historical", change: func(r *projections.ConnectorDeliveryRecorded) { r.ReceiverAttemptID = "" }},
		{name: "failed", change: func(r *projections.ConnectorDeliveryRecorded) { r.Status = "failed" }, wantError: true},
		{name: "other-invocation", change: func(r *projections.ConnectorDeliveryRecorded) { r.ReceiverAttemptID = uuid.NewString() }},
		{name: "other-command", change: func(r *projections.ConnectorDeliveryRecorded) { r.IdempotencyKey = "other" }, wantError: true},
		{name: "other-destination", change: func(r *projections.ConnectorDeliveryRecorded) { r.Destination = "connector.rollback" }, wantError: true},
		{name: "missing-outbox", change: func(r *projections.ConnectorDeliveryRecorded) { r.OutboxID = nil }, wantError: true},
		{name: "malformed-id", change: func(r *projections.ConnectorDeliveryRecorded) { r.ReceiverAttemptID = "not-a-uuid" }, wantError: true},
		{name: "legacy-sentinel", change: func(r *projections.ConnectorDeliveryRecorded) {
			r.ReceiverAttemptID = "00000000-0000-0000-0000-000000000226"
		}, wantError: true},
		{name: "other-tenant", foreignTenant: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, receipt, ids := connectorReceiverFixture(t)
			outboxID := *receipt.OutboxID
			if tc.change != nil {
				tc.change(&receipt)
			}
			tenant := tenantA
			if tc.foreignTenant {
				tenant = tenantB
			}
			event := connectorReceiverEvent(t, tenant, receipt)
			if tc.version != 0 {
				event.SchemaVersion = tc.version
			}
			err := projections.New(s).Apply(t.Context(), event)
			if (err != nil) != tc.wantError {
				t.Fatalf("projection error=%v, wantError=%v", err, tc.wantError)
			}
			if got := receiverPendingIDs(t, s, outboxID); !reflect.DeepEqual(got, ids) {
				t.Fatalf("unproven receipt released an invocation: %v", got)
			}
			if tc.wantError {
				if _, err := s.GetConnectorDeliveryReceipt(t.Context(), tenant, receipt.ID); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("invalid binding did not roll back receipt: %v", err)
				}
			}
		})
	}
}

func connectorReceiverEvent(t *testing.T, tenant string, receipt projections.ConnectorDeliveryRecorded) events.Event {
	t.Helper()
	event := projectorEventForTenant(t, tenant, projections.EventConnectorDeliveryRecorded, receipt)
	if receipt.ReceiverAttemptID != "" {
		event.SchemaVersion = projections.ConnectorReceiverCompletionSchemaVersion
	}
	return event
}

func TestConnectorReceiverCompletionPrivacyKeepsHistoricalShapeClosed(t *testing.T) {
	payload := projections.ConnectorDeliveryRecorded{
		ID: uuid.NewString(), Destination: "connector.deploy", Connector: "receiver-fixture",
		Target: "owned-target", Status: "delivered", ReceiverAttemptID: uuid.NewString(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := events.PseudonymizeEventDataForSubject(data, tenantA, "receiver-fixture", projections.EventConnectorDeliveryRecorded, 1); err == nil || !strings.Contains(err.Error(), "pre-rewrite payload") {
		t.Fatalf("legacy privacy schema accepted completion field: %v", err)
	}
	if _, _, err := events.PseudonymizeEventDataForSubject(data, tenantA, "receiver-fixture", projections.EventConnectorDeliveryRecorded, projections.ConnectorReceiverCompletionSchemaVersion); err == nil || !strings.Contains(err.Error(), "rejects subject-bearing") {
		t.Fatalf("completion schema did not reach its closed privacy policy: %v", err)
	}
}
