// SPDX-License-Identifier: BUSL-1.1
package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Migration0211 assigns zero to existing rows; an old snapshot shape can omit
// the nullable column. Both must retain the current receipt when a lagging tail
// reaches an older authentic result already present in the same event history.
func TestRollbackLegacyCursorRebuiltBeforeLaggingTail(t *testing.T) {
	for _, legacy := range []string{"zero", "null"} {
		t.Run(legacy, func(t *testing.T) {
			ctx := t.Context()
			s, log, _ := recordingSpine(t)
			o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
			seedRollbackPredecessor(t, o)
			request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
			q, _, err := requestRollbackReceipt(ctx, o, request, "first-restore")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered', claim_attempts=1, claim_completed_at=now(), delivered_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, q.OutboxID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := o.RecordConnectorRollbackResult(ctx, tenantA, q.IdempotencyKey, 1, store.ConnectorDeliveryReceipt{
				OutboxID: &q.OutboxID, Destination: "connector.rollback", Connector: "f5", Target: request.Target, Fingerprint: "old-leaf", Status: "rolled_back",
			}); err != nil {
				t.Fatal(err)
			}
			var oldResult events.Event
			if err := log.Replay(ctx, 0, func(ev events.Event) error {
				if ev.Type != projections.EventConnectorDeliveryRecorded {
					return nil
				}
				var p projections.ConnectorDeliveryRecorded
				if err := json.Unmarshal(ev.Data, &p); err != nil {
					return err
				}
				if p.Status == "rolled_back" && p.OutboxID != nil && *p.OutboxID == q.OutboxID {
					oldResult = ev
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if oldResult.ID == "" {
				t.Fatal("missing authentic old result")
			}
			_, second, err := requestRollbackReceipt(ctx, o, request, "second-restore")
			if err != nil {
				t.Fatal(err)
			}
			// Keep the prior application's row bytes, replacing only the newly added
			// column with the value supplied by upgrade or an omitted snapshot field.
			var legacyCursor any = int64(0)
			if legacy == "null" {
				legacyCursor = nil
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE connector_delivery_receipts SET latest_event_sequence=$3 WHERE tenant_id=$1 AND id=$2`, tenantA, second.ID, legacyCursor)
				return err
			}); err != nil {
				t.Fatal(err)
			}

			// An existing shared NATS consumer can lag PostgreSQL after a prior boot's
			// catch-up. Build that durable cursor using the real API, stopping before
			// acknowledging the old result. No receipt projection runs during priming.
			pause := errors.New("controlled legacy-consumer pause")
			err = log.TailFrom(ctx, func(context.Context) (uint64, error) { return 0, nil }, func(ev events.Event) error {
				if ev.Sequence == oldResult.Sequence {
					return pause
				}
				return nil
			})
			if !errors.Is(err, pause) {
				t.Fatalf("consumer prime: %v", err)
			}
			head, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.AdvanceProjectionCheckpoint(ctx, head); err != nil {
				t.Fatal(err)
			}
			// Warm startup sees an already-current SQL checkpoint, so it does not
			// backfill the newly added cursor from the already-projected older history.
			if err := projections.New(s).ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			var resumed uint64
			err = log.TailFrom(ctx, s.ProjectionCheckpoint, func(ev events.Event) error {
				resumed = ev.Sequence
				if err := projections.New(s).Apply(ctx, ev); err != nil {
					return err
				}
				return pause
			})
			if !errors.Is(err, pause) || resumed != oldResult.Sequence {
				t.Fatalf("legacy tail did not resume old result: seq=%d err=%v", resumed, err)
			}

			read, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, second.ID)
			if err != nil {
				t.Fatal(err)
			}
			if read.Status != "rollback_queued" || read.IdempotencyKey != "second-restore" {
				t.Fatalf("legacy %s cursor let older result replace retained request: sequence=%d receipt=%s key=%s", legacy, oldResult.Sequence, read.Status, read.IdempotencyKey)
			}
		})
	}
}

func TestRollbackLegacyRebuildFailurePreservesPriorReadModel(t *testing.T) {
	ctx := t.Context()
	s, log, _ := recordingSpine(t)
	o := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	seedRollbackPredecessor(t, o)
	request := orchestrator.ConnectorRollbackRequest{Connector: "f5", Target: "execution-route", PredecessorFingerprint: "old-leaf", SuccessorFingerprint: "new-leaf"}
	_, prior, err := requestRollbackReceipt(ctx, o, request, "retained-restore")
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, head); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE connector_delivery_receipts SET latest_event_sequence=0 WHERE tenant_id=$1 AND id=$2`, tenantA, prior.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A retained event with an unsupported known schema must stop the rebuild.
	// The fixture controls the log failure, not the projected result being checked.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantA, SchemaVersion: 999, Data: json.RawMessage(`{"id":"unsupported","status":"rolled_back"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).ProjectCatchUp(ctx, log); err == nil {
		t.Fatal("legacy rebuild accepted unsupported retained schema")
	}
	got, err := s.GetConnectorDeliveryReceipt(ctx, tenantA, prior.ID)
	if err != nil || got.Status != "rollback_queued" || got.IdempotencyKey != "retained-restore" {
		t.Fatalf("failed rebuild changed prior receipt: %+v %v", got, err)
	}
	if legacy, err := s.ConnectorRollbackProjectionNeedsRebuild(ctx); err != nil || !legacy {
		t.Fatalf("failed rebuild hid next boot recovery: %t %v", legacy, err)
	}
	if after, err := s.ProjectionCheckpoint(ctx); err != nil || after != head {
		t.Fatalf("failed rebuild advanced checkpoint: %d %v", after, err)
	}
}
