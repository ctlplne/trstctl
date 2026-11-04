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

// MDM device check-ins (N9). A check-in is queued only with the exact
// operation approval it names, which its source event consumes; the relay job
// is enqueued in the same tenant transaction, so an approval is spent on
// exactly one job and a retried command finds the same check-in.

// MDMCheckInID is the check-in an approval request authorizes.
func MDMCheckInID(tenantID, approvalRequestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-check-in\x00"+tenantID+"\x00"+approvalRequestID)).String()
}

// MDMCheckInJobKey is the relay job a check-in queues.
func MDMCheckInJobKey(checkInID string) string { return "mdm-check-in:" + checkInID }

// QueueMDMCheckIn consumes one exact approval beside the check-in projection
// and the relay job. The intent carries the schedule's connection (base URL,
// token reference, client credentials) for the relay; it must name the same
// check-in, device and relay as the event.
func (o *Orchestrator) QueueMDMCheckIn(ctx context.Context, tenantID string, queued projections.MDMCheckInQueued, intent relay.MDMCheckInIntent) error {
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return errors.New("MDM check-in execution is not configured")
	}
	if err := projections.ValidateMDMCheckInQueued(queued); err != nil {
		return err
	}
	if queued.ID != MDMCheckInID(tenantID, queued.Approval.RequestID) {
		return errors.New("MDM check-in ID differs from its approved command")
	}
	if intent.ID != queued.ID || intent.MDM != queued.MDM || intent.DeviceID != queued.DeviceID || intent.RequiredAgentID != queued.RelayAgentID {
		return errors.New("MDM check-in job differs from its approved check-in")
	}
	if err := relay.ValidateMDMCheckInIntent(intent); err != nil {
		return err
	}
	raw, err := json.Marshal(queued)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(intent)
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
			canonical, err = o.log.Append(ctx, events.Event{ID: queued.ID, TenantID: tenantID, Type: projections.EventMDMCheckInQueued, Data: raw})
			if err != nil {
				return err
			}
		}
		if canonical.ID != queued.ID || canonical.Type != projections.EventMDMCheckInQueued || canonical.TenantID != tenantID || canonical.SchemaVersion != 1 {
			return fmt.Errorf("%w: MDM check-in source envelope changed", store.ErrIdempotencyConflict)
		}
		matches, err := operationApprovalEventDataMatches(canonical, raw, tenantID, queued.Approval.Requester)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("%w: MDM approved check-in changed", store.ErrIdempotencyConflict)
		}
		if err := validateOperationApprovalBoundActor(canonical.Actor, tenantID, queued.Approval.Requester); err != nil {
			return err
		}
		if err := o.proj.ApplyTx(ctx, tx, canonical); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{TenantID: tenantID, Destination: relay.KindMDMCheckIn,
			IdempotencyKey: MDMCheckInJobKey(queued.ID), Payload: payload,
			RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: queued.RelayAgentID})
		return err
	})
}

// RecordMDMCheckedIn records the MDM's acknowledgement from the relay's checked
// report. Recording it twice records it once.
func (o *Orchestrator) RecordMDMCheckedIn(ctx context.Context, tenantID string, checked projections.MDMCheckedIn) error {
	data, err := json.Marshal(checked)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-checked-in\x00"+tenantID+"\x00"+checked.ID)).String()
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventMDMCheckedIn, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != id || ev.Type != projections.EventMDMCheckedIn {
		return fmt.Errorf("%w: MDM check-in result changed", store.ErrIdempotencyConflict)
	}
	return nil
}
