// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// DestinationDocRecord is the outbox destination of one sync of a
// customer's documentation record in a documentation target (MSP-14).
const DestinationDocRecord = "provider.doc_record"

// DocRecordRequest is one sync: the target and the interval it belongs to.
type DocRecordRequest struct {
	TargetID string    `json:"target_id"`
	Bucket   time.Time `json:"bucket"`
}

// DocRecordKey is the outbox key of one sync: one per customer, target and
// interval.
func DocRecordKey(targetID string, bucket time.Time) string {
	return "doc-record:" + targetID + ":" + bucket.UTC().Format(time.RFC3339)
}

// QueueDocRecord queues one sync of the customer's record in the target for
// the interval; the same interval twice queues it once.
func (o *Orchestrator) QueueDocRecord(ctx context.Context, tenantID, targetID string, bucket time.Time) (bool, error) {
	if o.outbox == nil {
		return false, errors.New("orchestrator: documentation record outbox is unavailable")
	}
	payload, err := json.Marshal(DocRecordRequest{TargetID: targetID, Bucket: bucket.UTC()})
	if err != nil {
		return false, err
	}
	queued := false
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		queued, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationDocRecord,
			IdempotencyKey: DocRecordKey(targetID, bucket), Payload: payload})
		return err
	})
	return queued, err
}

// RecordDocRecord records one sync's outcome, serialized per customer and
// target.
func (o *Orchestrator) RecordDocRecord(ctx context.Context, tenantID string, outcome projections.DocRecordEvent) error {
	outcome.Reason = truncateText(strings.TrimSpace(outcome.Reason), 2000)
	if err := projections.ValidateDocRecordEvent(outcome); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "doc-record|"+tenantID+"|"+outcome.TargetID); err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventDocRecordRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
}
