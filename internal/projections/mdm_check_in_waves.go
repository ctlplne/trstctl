// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// N9-L2: a check-in wave asks an MDM to have every device of a renewal wave
// check in under one approval. The wave's source event consumes the approval
// once and queues one check-in per device, each with its own relay job and
// its own result, as N9's single check-ins.
const EventMDMCheckInWaveQueued = "mdm.device.check_in_wave_queued"

// MaxMDMCheckInWaveDevices bounds one wave.
const MaxMDMCheckInWaveDevices = 200

// MDMCheckInWaveDevice is one device of a wave and the check-in it queues.
type MDMCheckInWaveDevice struct {
	CheckInID  string `json:"check_in_id"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
}

// MDMCheckInWaveQueued is the payload of mdm.device.check_in_wave_queued.
type MDMCheckInWaveQueued struct {
	ID           string                     `json:"id"`
	MDM          string                     `json:"mdm"`
	RelayAgentID string                     `json:"relay_agent_id"`
	Devices      []MDMCheckInWaveDevice     `json:"devices"`
	Approval     store.OperationApprovalUse `json:"approval"`
}

// ValidateMDMCheckInWaveQueued checks a wave's closed shape.
func ValidateMDMCheckInWaveQueued(q MDMCheckInWaveQueued) error {
	if q.ID == "" || (q.MDM != "intune" && q.MDM != "jamf") || q.RelayAgentID == "" || q.Approval.RequestID == "" ||
		q.Approval.ResourceKind != "mdm_check_in_wave" || q.Approval.Action != "check_in" {
		return errors.New("projections: an MDM check-in wave needs its id, intune or jamf, the relay and its approval")
	}
	if len(q.Devices) == 0 || len(q.Devices) > MaxMDMCheckInWaveDevices {
		return fmt.Errorf("projections: an MDM check-in wave checks in 1 to %d devices", MaxMDMCheckInWaveDevices)
	}
	devices, checkIns := map[string]bool{}, map[string]bool{}
	for _, d := range q.Devices {
		if d.CheckInID == "" || d.DeviceID == "" || devices[d.DeviceID] || checkIns[d.CheckInID] {
			return errors.New("projections: an MDM check-in wave names each device once, with its own check-in")
		}
		devices[d.DeviceID], checkIns[d.CheckInID] = true, true
	}
	return nil
}

func init() {
	knownSchemaVersions[EventMDMCheckInWaveQueued] = map[int]bool{1: true}
}

func (p *Projector) applyMDMCheckInWaveTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventMDMCheckInWaveQueued {
		return false, nil
	}
	var q MDMCheckInWaveQueued
	if err := json.Unmarshal(e.Data, &q); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidateMDMCheckInWaveQueued(q); err != nil {
		return true, err
	}
	if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, q.Approval, e.ID, e.Time); err != nil {
		return true, err
	}
	if err := p.store.ApplyMDMCheckInWaveQueuedTx(ctx, tx, e.TenantID, store.MDMCheckInWave{ID: q.ID, MDM: q.MDM,
		RelayAgentID: q.RelayAgentID, Reason: q.Approval.Reason, ApprovalRequestID: q.Approval.RequestID,
		RequestedBy: q.Approval.Requester, DeviceCount: len(q.Devices), QueuedAt: e.Time}, e.Sequence); err != nil {
		return true, err
	}
	for _, d := range q.Devices {
		if err := p.store.ApplyMDMCheckInQueuedTx(ctx, tx, e.TenantID, store.MDMCheckIn{ID: d.CheckInID, MDM: q.MDM,
			DeviceID: d.DeviceID, DeviceName: d.DeviceName, RelayAgentID: q.RelayAgentID, Reason: q.Approval.Reason,
			ApprovalRequestID: q.Approval.RequestID, RequestedBy: q.Approval.Requester, QueuedAt: e.Time}, e.Sequence); err != nil {
			return true, err
		}
	}
	return true, nil
}

func addMDMCheckInWavePrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		clear  = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventMDMCheckInWaveQueued, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/mdm", opaque), privacyRule("/relay_agent_id", opaque),
		privacyRule("/devices/*/check_in_id", opaque), privacyRule("/devices/*/device_id", opaque),
		privacyRule("/devices/*/device_name", clear),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs", opaque),
		privacyRule("/approval/issuance", opaque))
}

func addMDMCheckInWavePrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventMDMCheckInWaveQueued, 1}] = privacyPayloadShape[MDMCheckInWaveQueued]()
}
