// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// DestinationRMMInventory is the outbox destination of one inventory of a
// customer's devices in an RMM target (MSP-9): list them under the mapped
// organization, map them to the customer's agents, report agent health back.
const DestinationRMMInventory = "provider.rmm_inventory"

// RMMInventoryRequest is the payload of an inventory.
type RMMInventoryRequest struct {
	TargetID string    `json:"target_id"`
	Bucket   time.Time `json:"bucket"`
}

// RMMInventoryKey is the outbox key of one inventory: one per customer,
// target and sweep interval.
func RMMInventoryKey(targetID string, bucket time.Time) string {
	return "rmm-inventory:" + targetID + ":" + bucket.UTC().Format(time.RFC3339)
}

// maxRMMDevicesPerInventory bounds one inventory's work (backpressure).
const maxRMMDevicesPerInventory = 5000

// QueueRMMInventory enqueues one inventory of a customer's devices in a
// target; the same interval again is a no-op.
func (o *Orchestrator) QueueRMMInventory(ctx context.Context, tenantID, targetID string, bucket time.Time) (bool, error) {
	if o.outbox == nil {
		return false, errors.New("orchestrator: RMM inventory outbox is unavailable")
	}
	payload, err := json.Marshal(RMMInventoryRequest{TargetID: targetID, Bucket: bucket.UTC()})
	if err != nil {
		return false, err
	}
	queued := false
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		queued, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: DestinationRMMInventory,
			IdempotencyKey: RMMInventoryKey(targetID, bucket), Payload: payload})
		return err
	})
	return queued, err
}

// RecordRMMInventory records what an inventory found: one event for each
// device whose observed fields changed (its name, organization, agent and
// health), and one marking each recorded device the RMM no longer lists as
// gone. It reports how many events it appended.
func (o *Orchestrator) RecordRMMInventory(ctx context.Context, tenantID, targetID string, devices []projections.RMMDeviceEvent) (int, error) {
	if len(devices) > maxRMMDevicesPerInventory {
		return 0, fmt.Errorf("orchestrator: an inventory of %d devices is over the %d bound", len(devices), maxRMMDevicesPerInventory)
	}
	appended := 0
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "rmm-inventory|"+tenantID+"|"+targetID); err != nil {
			return err
		}
		existing, err := store.RMMDevicesTx(ctx, tx, tenantID, targetID)
		if err != nil {
			return err
		}
		known := make(map[string]store.RMMDevice, len(existing))
		for _, d := range existing {
			known[d.DeviceID] = d
		}
		seen := make(map[string]bool, len(devices))
		changes := make([]projections.RMMDeviceEvent, 0, len(devices))
		for _, d := range devices {
			d.TargetID, d.Present = targetID, true
			seen[d.DeviceID] = true
			if cur, ok := known[d.DeviceID]; ok && cur.Present && cur.DeviceName == d.DeviceName && cur.OrgID == d.OrgID &&
				cur.AgentID == d.AgentID && cur.AgentMatch == d.AgentMatch && cur.Health == d.Health {
				continue
			}
			changes = append(changes, d)
		}
		for _, cur := range existing {
			if cur.Present && !seen[cur.DeviceID] {
				changes = append(changes, projections.RMMDeviceEvent{TargetID: targetID, DeviceID: cur.DeviceID, DeviceName: cur.DeviceName,
					OrgID: cur.OrgID})
			}
		}
		for _, change := range changes {
			if err := projections.ValidateRMMDeviceEvent(projections.EventRMMDeviceObserved, change); err != nil {
				return fmt.Errorf("orchestrator: %w", err)
			}
			payload, err := json.Marshal(change)
			if err != nil {
				return err
			}
			ev, err := o.log.Append(ctx, events.Event{Type: projections.EventRMMDeviceObserved, TenantID: tenantID, Data: payload})
			if err != nil {
				return err
			}
			if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
				return err
			}
			appended++
		}
		return nil
	})
	return appended, err
}
