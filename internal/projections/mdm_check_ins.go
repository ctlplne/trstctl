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

// MDM device check-ins (N9): a check-in queued for the MDM schedule's relay,
// consuming the exact operation approval it carries, and the MDM's
// acknowledgement the relay's checked report carries back.
const (
	EventMDMCheckInQueued = "mdm.device.check_in_queued"
	EventMDMCheckedIn     = "mdm.device.checked_in"
)

// MDMCheckInQueued is the payload of mdm.device.check_in_queued.
type MDMCheckInQueued struct {
	ID           string                     `json:"id"`
	MDM          string                     `json:"mdm"`
	DeviceID     string                     `json:"device_id"`
	DeviceName   string                     `json:"device_name,omitempty"`
	RelayAgentID string                     `json:"relay_agent_id"`
	Approval     store.OperationApprovalUse `json:"approval"`
}

// MDMCheckedIn is the payload of mdm.device.checked_in.
type MDMCheckedIn struct {
	ID             string `json:"id"`
	ProviderStatus int    `json:"provider_status"`
}

// ValidateMDMCheckInQueued checks a queued check-in's closed shape.
func ValidateMDMCheckInQueued(q MDMCheckInQueued) error {
	if q.ID == "" || (q.MDM != "intune" && q.MDM != "jamf") || q.DeviceID == "" || q.RelayAgentID == "" ||
		q.Approval.RequestID == "" || q.Approval.ResourceKind != "mdm_device" || q.Approval.Action != "check_in" {
		return errors.New("projections: an MDM check-in needs its id, intune or jamf, the device, the relay and its approval")
	}
	return nil
}

func init() {
	for _, typ := range []string{EventMDMCheckInQueued, EventMDMCheckedIn} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyMDMCheckInTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventMDMCheckInQueued:
		var q MDMCheckInQueued
		if err := json.Unmarshal(e.Data, &q); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateMDMCheckInQueued(q); err != nil {
			return true, err
		}
		if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, q.Approval, e.ID, e.Time); err != nil {
			return true, err
		}
		return true, p.store.ApplyMDMCheckInQueuedTx(ctx, tx, e.TenantID, store.MDMCheckIn{ID: q.ID, MDM: q.MDM,
			DeviceID: q.DeviceID, DeviceName: q.DeviceName, RelayAgentID: q.RelayAgentID, Reason: q.Approval.Reason,
			ApprovalRequestID: q.Approval.RequestID, RequestedBy: q.Approval.Requester, QueuedAt: e.Time}, e.Sequence)
	case EventMDMCheckedIn:
		var c MDMCheckedIn
		if err := json.Unmarshal(e.Data, &c); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		return true, p.store.ApplyMDMCheckedInTx(ctx, tx, e.TenantID, c.ID, c.ProviderStatus, e.Time, e.Sequence)
	}
	return false, nil
}

func addMDMCheckInPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		clear  = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventMDMCheckInQueued, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/mdm", opaque), privacyRule("/device_id", opaque),
		privacyRule("/device_name", clear), privacyRule("/relay_agent_id", opaque),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", clear), privacyRule("/approval/evidence_refs", opaque),
		privacyRule("/approval/issuance", opaque))
	policies[privacyEventPolicyKey{EventMDMCheckedIn, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/provider_status", opaque))
}

func addMDMCheckInPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventMDMCheckInQueued, 1}] = privacyPayloadShape[MDMCheckInQueued]()
	shapes[privacyEventPolicyKey{EventMDMCheckedIn, 1}] = privacyPayloadShape[MDMCheckedIn]()
}
