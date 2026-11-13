// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DestinationRMMAction is the outbox destination of one agent action run
// through an RMM on a customer's device (MSP-9): install, upgrade or remove.
const DestinationRMMAction = "provider.rmm_action"

var (
	// ErrRMMDeviceUnknown refuses an action on a device the customer's
	// inventory does not record as present.
	ErrRMMDeviceUnknown = errors.New("orchestrator: the customer's RMM inventory lists no such device")
	// ErrRMMActionInFlight refuses an action while another is still
	// running on the device.
	ErrRMMActionInFlight = errors.New("orchestrator: an agent action is still running on this device")
)

// RMMActionKey is the outbox key of one requested action: the request's own
// event.
func RMMActionKey(eventID string) string { return "rmm-action:" + eventID }

// RMMActionEventID is the event that records one operator request: the same
// request retried finds it and queues nothing more.
func RMMActionEventID(tenantID, targetID, deviceID, requestKey string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("rmm-action\x00"+tenantID+"\x00"+targetID+"\x00"+deviceID+"\x00"+requestKey)).String()
}

// QueueRMMAction records an agent action requested on one of the customer's
// devices and queues it in the same tenant transaction. requestKey is the
// caller's idempotency key: the same request twice queues one action. It
// refuses a device the customer's inventory does not list as present, and a
// device with an action still in flight.
func (o *Orchestrator) QueueRMMAction(ctx context.Context, tenantID, targetID, deviceID, action, by, requestKey string) (string, error) {
	if o.outbox == nil {
		return "", errors.New("orchestrator: RMM action outbox is unavailable")
	}
	if strings.TrimSpace(requestKey) == "" {
		return "", errors.New("orchestrator: an RMM action request carries its idempotency key")
	}
	ev := projections.RMMDeviceEvent{TargetID: targetID, DeviceID: deviceID, Action: action, By: strings.TrimSpace(by)}
	if err := projections.ValidateRMMDeviceEvent(projections.EventRMMDeviceActionRequested, ev); err != nil {
		return "", fmt.Errorf("orchestrator: %w", err)
	}
	eventID := RMMActionEventID(tenantID, targetID, deviceID, requestKey)
	if _, found, err := o.log.EventByID(ctx, eventID); err != nil || found {
		return eventID, err
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, found, err := store.RMMDeviceForTx(ctx, tx, tenantID, targetID, deviceID)
		if err != nil {
			return err
		}
		if !found || !cur.Present {
			return ErrRMMDeviceUnknown
		}
		if cur.ActionStatus == store.RMMActionRequested {
			return ErrRMMActionInFlight
		}
		appended, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventRMMDeviceActionRequested, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, appended); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationRMMAction,
			IdempotencyKey: RMMActionKey(appended.ID), Payload: appended.Data})
		return err
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
}

// RecordRMMActionOutcome records the outcome of the request still in flight
// on a device; an outcome for any other request is ignored.
func (o *Orchestrator) RecordRMMActionOutcome(ctx context.Context, tenantID string, outcome projections.RMMDeviceEvent) error {
	outcome.By = ""
	outcome.Reason = truncateText(strings.TrimSpace(outcome.Reason), 2000)
	if err := projections.ValidateRMMDeviceEvent(projections.EventRMMDeviceActionRecorded, outcome); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	payload, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, found, err := store.RMMDeviceForTx(ctx, tx, tenantID, outcome.TargetID, outcome.DeviceID)
		if err != nil || !found || cur.ActionEventID != outcome.Request || cur.ActionStatus != store.RMMActionRequested {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventRMMDeviceActionRecorded, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
}

// reconcileRMMAction re-enqueues the request still in flight whose
// transaction appended the event but did not commit its outbox entry.
func (o *Orchestrator) reconcileRMMAction(ctx context.Context, ev events.Event) (bool, error) {
	var req projections.RMMDeviceEvent
	if err := json.Unmarshal(ev.Data, &req); err != nil {
		return false, fmt.Errorf("decode retained RMM action: %w", err)
	}
	if err := projections.ValidateRMMDeviceEvent(ev.Type, req); err != nil {
		return false, err
	}
	inserted := false
	err := o.store.WithTenant(ctx, ev.TenantID, func(tx pgx.Tx) error {
		cur, found, err := store.RMMDeviceForTx(ctx, tx, ev.TenantID, req.TargetID, req.DeviceID)
		if err != nil || !found || cur.ActionEventID != ev.ID || cur.ActionStatus != store.RMMActionRequested {
			return err
		}
		inserted, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: ev.TenantID, Destination: DestinationRMMAction,
			IdempotencyKey: RMMActionKey(ev.ID), Payload: ev.Data})
		return err
	})
	return inserted, err
}
