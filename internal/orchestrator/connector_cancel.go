// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// Cancelling a target's in-flight connector work (A48).
//
// The command is one tenant transaction: the target row is locked so no new
// deploy or rollback is queued on the lane while it runs, every unfinished
// lane command is withdrawn or recalled, and each one gets a cancelled receipt
// appended as the same immutable connector.delivery.recorded evidence every
// other terminal outcome uses. A row the control-plane worker is executing is
// reported, not touched.

// CancelConnectorWorkRequest names the lane to drain and who asked.
type CancelConnectorWorkRequest struct {
	TargetID    string
	IdentityID  string
	Reason      string
	RequestedBy string
}

// ConnectorWorkCancelled is the durable outcome of one cancel command.
type ConnectorWorkCancelled struct {
	TargetID  string
	Withdrawn []int64
	Recalled  []int64
	Executing []int64
	Receipts  []store.ConnectorDeliveryReceipt
}

func connectorCancelReceiptID(tenantID string, outboxID int64) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte(fmt.Sprintf("connector-cancel-receipt\x00%s\x00%d", tenantID, outboxID))).String()
}

// CancelConnectorTargetWork withdraws queued and recalls leased work on one
// deployment target's lane. The receipts it returns are the operator's record
// of what stopped and, for a recalled row, what may already have happened.
func (o *Orchestrator) CancelConnectorTargetWork(ctx context.Context, tenantID string, in CancelConnectorWorkRequest) (ConnectorWorkCancelled, error) {
	req := CancelConnectorWorkRequest{
		TargetID: strings.TrimSpace(in.TargetID), IdentityID: strings.TrimSpace(in.IdentityID),
		Reason: strings.TrimSpace(in.Reason), RequestedBy: strings.TrimSpace(in.RequestedBy),
	}
	if _, err := uuid.Parse(req.TargetID); err != nil {
		return ConnectorWorkCancelled{}, errors.New("orchestrator: cancelling connector work needs an exact target id")
	}
	if req.IdentityID != "" {
		if _, err := uuid.Parse(req.IdentityID); err != nil {
			return ConnectorWorkCancelled{}, errors.New("orchestrator: cancelling connector work needs an exact identity id when one is named")
		}
	}
	if req.Reason == "" {
		return ConnectorWorkCancelled{}, errors.New("orchestrator: cancelling connector work needs a reason")
	}
	if req.RequestedBy == "" {
		if actor, ok := events.ActorFromContext(ctx); ok {
			req.RequestedBy = actor.Subject
		}
	}
	out := ConnectorWorkCancelled{TargetID: req.TargetID}
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var connectorName, targetName string
		if err := tx.QueryRow(ctx,
			`SELECT type, name FROM deployment_targets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
			tenantID, req.TargetID).Scan(&connectorName, &targetName); err != nil {
			return err
		}
		now := time.Now().UTC()
		cancelled, err := o.store.CancelConnectorTargetWorkTx(ctx, tx, tenantID, req.TargetID, req.IdentityID, now)
		if err != nil {
			return err
		}
		for _, c := range cancelled {
			switch c.Disposition {
			case store.ConnectorWorkExecuting:
				out.Executing = append(out.Executing, c.OutboxID)
				continue
			case store.ConnectorWorkRecalled:
				out.Recalled = append(out.Recalled, c.OutboxID)
			default:
				out.Withdrawn = append(out.Withdrawn, c.OutboxID)
			}
			receipt, err := o.recordCancelledReceiptTx(ctx, tx, tenantID, connectorName, targetName, req, c, now)
			if err != nil {
				return err
			}
			out.Receipts = append(out.Receipts, receipt)
		}
		return nil
	})
	if err != nil {
		return ConnectorWorkCancelled{}, fmt.Errorf("orchestrator: cancel connector work: %w", err)
	}
	return out, nil
}

// recordCancelledReceiptTx appends the cancelled receipt for one row. An
// existing receipt for the job (queued, verify pending) converges on the same
// outbox id; a job that never had one gets a deterministic receipt id so a
// retried command cannot mint a second record.
func (o *Orchestrator) recordCancelledReceiptTx(ctx context.Context, tx pgx.Tx, tenantID, connectorName, targetName string,
	req CancelConnectorWorkRequest, c store.ConnectorWorkCancellation, now time.Time) (store.ConnectorDeliveryReceipt, error) {
	outboxID := c.OutboxID
	pl := projections.ConnectorDeliveryRecorded{
		ID: connectorCancelReceiptID(tenantID, outboxID), OutboxID: &outboxID,
		Destination: c.Destination, Connector: connectorName, Target: targetName,
		Fingerprint: c.Fingerprint, Status: servedstatus.ConnectorCancelled,
		Reason: "cancelled by operator: " + req.Reason, IdempotencyKey: c.IdempotencyKey,
	}
	if c.IdentityID != "" {
		identityID := c.IdentityID
		pl.IdentityID = &identityID
	}
	if existing, err := o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID); err == nil {
		pl.ID, pl.Attempts, pl.RollbackRef = existing.ID, existing.Attempts, existing.RollbackRef
		if pl.Fingerprint == "" {
			pl.Fingerprint = existing.Fingerprint
		}
		if pl.IdentityID == nil && existing.IdentityID != nil {
			pl.IdentityID = existing.IdentityID
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return store.ConnectorDeliveryReceipt{}, err
	}
	switch c.Disposition {
	case store.ConnectorWorkRecalled:
		pl.Detail = "Recalled from enrolled agent " + c.ClaimedByAgentID + " while it held the lease: its next lease extension, " +
			"credential redemption and rollback authorization are refused and a late signed result is retained as a receipt, " +
			"not applied. The agent may already have changed the target; verify the listener and roll back if needed."
	default:
		pl.Detail = "Withdrawn before any agent or worker claimed it; the target was not changed by this command."
	}
	payload, err := json.Marshal(pl)
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	eventID := "connector-cancelled:" + pl.ID
	retained, err := o.log.Append(ctx, events.Event{ID: eventID,
		Type: projections.EventConnectorDeliveryRecorded, TenantID: tenantID, Data: payload})
	if err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	if retained.ID != eventID || retained.TenantID != tenantID ||
		retained.Type != projections.EventConnectorDeliveryRecorded || !bytes.Equal(retained.Data, payload) {
		return store.ConnectorDeliveryReceipt{}, fmt.Errorf("%w: cancelled receipt differs from retained event", store.ErrIdempotencyConflict)
	}
	if err := o.proj.ApplyTx(ctx, tx, retained); err != nil {
		return store.ConnectorDeliveryReceipt{}, err
	}
	_ = now
	return o.store.GetConnectorDeliveryReceiptForOutboxTx(ctx, tx, tenantID, outboxID)
}
