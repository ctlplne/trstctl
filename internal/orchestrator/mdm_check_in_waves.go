// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// N9-L2: a check-in wave is queued only with the exact operation approval it
// names, which its source event consumes once; every device's check-in and
// relay job are written in the same tenant transaction, so one approval is
// spent on exactly the wave it named and a retried command finds the same
// wave.

// MDMCheckInWaveID is the wave an approval request authorizes.
func MDMCheckInWaveID(tenantID, approvalRequestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-check-in-wave\x00"+tenantID+"\x00"+approvalRequestID)).String()
}

// MDMCheckInWaveCheckInID is one device's check-in in a wave.
func MDMCheckInWaveCheckInID(tenantID, approvalRequestID, deviceID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-check-in\x00"+tenantID+"\x00"+approvalRequestID+"\x00"+deviceID)).String()
}

// QueueMDMCheckInWave consumes one exact approval beside the wave, its
// devices' check-ins and their relay jobs. Each intent names its device's
// check-in, device and the wave's relay.
func (o *Orchestrator) QueueMDMCheckInWave(ctx context.Context, tenantID string, queued projections.MDMCheckInWaveQueued, intents []relay.MDMCheckInIntent) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("MDM check-in execution is not configured")
	}
	if err := projections.ValidateMDMCheckInWaveQueued(queued); err != nil {
		return err
	}
	if queued.ID != MDMCheckInWaveID(tenantID, queued.Approval.RequestID) {
		return errors.New("MDM check-in wave ID differs from its approved command")
	}
	if len(intents) != len(queued.Devices) {
		return errors.New("MDM check-in wave jobs differ from its devices")
	}
	payloads := make([][]byte, len(intents))
	for i, intent := range intents {
		d := queued.Devices[i]
		if d.CheckInID != MDMCheckInWaveCheckInID(tenantID, queued.Approval.RequestID, d.DeviceID) || intent.ID != d.CheckInID ||
			intent.MDM != queued.MDM || intent.DeviceID != d.DeviceID || intent.RequiredAgentID != queued.RelayAgentID {
			return errors.New("MDM check-in wave job differs from its approved device")
		}
		if err := relay.ValidateMDMCheckInIntent(intent); err != nil {
			return err
		}
		raw, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		payloads[i] = raw
	}
	raw, err := json.Marshal(queued)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		canonical, found, err := o.log.EventByID(ctx, queued.ID)
		if err != nil {
			return err
		}
		if !found {
			if _, err := o.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, queued.Approval, time.Now().UTC()); err != nil {
				return err
			}
			canonical, err = o.log.Append(ctx, events.Event{ID: queued.ID, TenantID: tenantID, Type: projections.EventMDMCheckInWaveQueued, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != queued.ID || canonical.Type != projections.EventMDMCheckInWaveQueued || canonical.TenantID != tenantID || canonical.SchemaVersion != 1 {
			return fmt.Errorf("%w: MDM check-in wave source envelope changed", store.ErrIdempotencyConflict)
		}
		matches, err := operationApprovalEventDataMatches(canonical, raw, tenantID, queued.Approval.Requester)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("%w: MDM approved check-in wave changed", store.ErrIdempotencyConflict)
		}
		if err := validateOperationApprovalBoundActor(canonical.Actor, tenantID, queued.Approval.Requester); err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		for i, d := range queued.Devices {
			if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: relay.KindMDMCheckIn,
				IdempotencyKey: MDMCheckInJobKey(d.CheckInID), Payload: payloads[i],
				RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: queued.RelayAgentID}); err != nil {
				return err
			}
		}
		return nil
	})
}
