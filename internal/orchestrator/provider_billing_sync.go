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
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DestinationBillingSync is the outbox destination of a customer's signed
// usage period pushed to a billing target (MSP-2).
const DestinationBillingSync = "provider.billing_sync"

// BillingSyncPushKey is the outbox idempotency key of one customer's period
// for one target: the same period can be queued only once, and the receiver
// sees the same key on every retry.
func BillingSyncPushKey(targetID string, periodStart time.Time) string {
	return "billing-sync:" + targetID + ":" + periodStart.UTC().Format(time.RFC3339)
}

func billingSyncAlertKey(kind, targetID string, periodStart time.Time) string {
	return kind + ":" + targetID + ":" + periodStart.UTC().Format(time.RFC3339)
}

// existingBillingSyncStatus reads a period's state in the command's tenant
// transaction ("" when it was never recorded).
func existingBillingSyncStatus(ctx context.Context, tx pgx.Tx, tenantID, targetID string, periodStart time.Time) (status, reason string, err error) {
	err = tx.QueryRow(ctx, `SELECT status, reason FROM provider_billing_sync_pushes
		WHERE tenant_id = $1 AND target_id = $2 AND period_start = $3`, tenantID, targetID, periodStart.UTC()).Scan(&status, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	return status, reason, err
}

// QueueBillingSyncPush records a customer's signable period as queued and
// enqueues its delivery in the same tenant transaction. A period already
// queued, delivered or failed is left alone (false), so a second sweep, a
// restart or a retry can never send it twice; a held period moves to queued.
func (o *Orchestrator) QueueBillingSyncPush(ctx context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error) {
	if err := projections.ValidateBillingSyncPushEvent(projections.EventBillingSyncQueued, push); err != nil {
		return false, fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(push)
	if err != nil {
		return false, err
	}
	queued := false
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		status, _, err := existingBillingSyncStatus(ctx, tx, tenantID, push.TargetID, push.PeriodStart)
		if err != nil {
			return err
		}
		if status != "" && status != store.BillingSyncHeld {
			return nil
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventBillingSyncQueued, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		queued, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationBillingSync,
			IdempotencyKey: BillingSyncPushKey(push.TargetID, push.PeriodStart), Payload: ev.Data,
		})
		return err
	})
	return queued, err
}

// HoldBillingSyncPush records a customer's period that cannot be signed and
// raises one alert for it; nothing is sent. A period already queued,
// delivered or failed is left alone, and a held period is recorded again
// only when its reason changed.
func (o *Orchestrator) HoldBillingSyncPush(ctx context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error) {
	push.EvidenceJWS, push.Lines = "", nil
	if err := projections.ValidateBillingSyncPushEvent(projections.EventBillingSyncHeld, push); err != nil {
		return false, fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(push)
	if err != nil {
		return false, err
	}
	held := false
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		status, reason, err := existingBillingSyncStatus(ctx, tx, tenantID, push.TargetID, push.PeriodStart)
		if err != nil {
			return err
		}
		if (status != "" && status != store.BillingSyncHeld) || (status == store.BillingSyncHeld && reason == push.Reason) {
			return nil
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventBillingSyncHeld, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		held = true
		_, err = o.enqueueBillingSyncAlertTx(ctx, tx, tenantID, notify.KindBillingSyncHeld, push)
		return err
	})
	return held, err
}

// RecordBillingSyncOutcome records a queued period's delivery or terminal
// failure; a failure raises an alert.
func (o *Orchestrator) RecordBillingSyncOutcome(ctx context.Context, tenantID string, push projections.BillingSyncPushEvent, delivered bool) error {
	eventType := projections.EventBillingSyncFailed
	if delivered {
		eventType = projections.EventBillingSyncDelivered
	}
	push.EvidenceJWS, push.Lines = "", nil
	if err := projections.ValidateBillingSyncPushEvent(eventType, push); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(push)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		status, _, err := existingBillingSyncStatus(ctx, tx, tenantID, push.TargetID, push.PeriodStart)
		if err != nil {
			return err
		}
		if status != store.BillingSyncQueued {
			return nil
		}
		ev, err := o.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		if !delivered {
			_, err = o.enqueueBillingSyncAlertTx(ctx, tx, tenantID, notify.KindBillingSyncFailed, push)
		}
		return err
	})
}

func (o *Orchestrator) enqueueBillingSyncAlertTx(ctx context.Context, tx pgx.Tx, tenantID, kind string, push projections.BillingSyncPushEvent) (bool, error) {
	if o.outbox == nil {
		return false, errors.New("orchestrator: billing sync alert outbox is unavailable")
	}
	period := push.PeriodStart.UTC().Format("2006-01-02") + " to " + push.PeriodEnd.UTC().Format("2006-01-02")
	detail := "The usage period " + period + " for billing target " + push.TargetID
	switch kind {
	case notify.KindBillingSyncHeld:
		detail += " was not sent because it cannot be signed: " + strings.TrimSpace(push.Reason)
	default:
		detail += " could not be delivered: " + strings.TrimSpace(push.Reason)
	}
	key := billingSyncAlertKey(kind, push.TargetID, push.PeriodStart)
	payload, err := json.Marshal(notify.Alert{
		Kind: kind, TenantID: tenantID, OperationID: key, Severity: notify.AlertSeverityWarning,
		Subject: "billing target " + push.TargetID, Detail: detail,
	})
	if err != nil {
		return false, err
	}
	return o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: notify.DestinationBillingSync, IdempotencyKey: key, Payload: payload})
}

// reconcileBillingSync re-enqueues a queued period's delivery, or a held or
// failed period's alert, whose transaction appended the event but did not
// commit the outbox entry.
func (o *Orchestrator) reconcileBillingSync(ctx context.Context, ev events.Event) (bool, error) {
	var push projections.BillingSyncPushEvent
	if err := json.Unmarshal(ev.Data, &push); err != nil {
		return false, fmt.Errorf("decode retained billing sync push: %w", err)
	}
	if err := projections.ValidateBillingSyncPushEvent(ev.Type, push); err != nil {
		return false, err
	}
	inserted := false
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		var err error
		switch ev.Type {
		case projections.EventBillingSyncQueued:
			inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
				TenantID: ev.TenantID, Destination: DestinationBillingSync,
				IdempotencyKey: BillingSyncPushKey(push.TargetID, push.PeriodStart), Payload: ev.Data,
			})
		case projections.EventBillingSyncHeld:
			inserted, err = o.enqueueBillingSyncAlertTx(ctx, tx, ev.TenantID, notify.KindBillingSyncHeld, push)
		case projections.EventBillingSyncFailed:
			inserted, err = o.enqueueBillingSyncAlertTx(ctx, tx, ev.TenantID, notify.KindBillingSyncFailed, push)
		}
		return err
	})
	return inserted, err
}
