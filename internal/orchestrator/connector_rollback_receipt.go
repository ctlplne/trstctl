// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RequestConnectorRollbackWithReceipt publishes the queued receipt in the same
// transaction that makes the job claimable. A fast agent cannot complete before
// that receipt exists, and a repeat returns the canonical tenant/outbox row.
func (o *Orchestrator) RequestConnectorRollbackWithReceipt(
	ctx context.Context, tenantID string, in ConnectorRollbackRequest, receipt store.ConnectorDeliveryReceipt,
) (ConnectorRollbackQueued, store.ConnectorDeliveryReceipt, error) {
	var identityID *string
	if value := strings.TrimSpace(in.IdentityID); value != "" {
		identityID = &value
	}
	var recorded store.ConnectorDeliveryReceipt
	queued, err := o.requestConnectorRollback(ctx, tenantID, in, func(tx pgx.Tx, q ConnectorRollbackQueued, fresh bool) error {
		if !fresh {
			// A repeat joins pending work. Do not reset its already-recorded result.
			existing, err := o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, q.OutboxID)
			if err == nil {
				recorded = existing
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		payload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
			ID: uuid.NewString(), OutboxID: &q.OutboxID, IdentityID: identityID,
			Destination: DestinationConnectorRollback, Connector: strings.TrimSpace(in.Connector), Target: receipt.Target,
			Fingerprint: strings.TrimSpace(in.SuccessorFingerprint), Status: "rollback_queued", Attempts: 1,
			Reason: receipt.Reason, Detail: receipt.Detail, RollbackRef: receipt.RollbackRef,
			IdempotencyKey: receipt.IdempotencyKey,
		})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		recorded, err = o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, q.OutboxID)
		return err
	})
	return queued, recorded, err
}
