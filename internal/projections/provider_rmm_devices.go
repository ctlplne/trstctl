// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A customer's RMM devices (MSP-9): what the RMM lists under the customer's
// organization and which agent each maps to (observed, recorded only when
// something changed), and the agent action run through the RMM (requested,
// then recorded with its outcome). The tenant is the customer.
const (
	EventRMMDeviceObserved        = "provider.rmm_device.observed"
	EventRMMDeviceActionRequested = "provider.rmm_device.action_requested"
	EventRMMDeviceActionRecorded  = "provider.rmm_device.action_recorded"
)

// RMMDeviceEvent is the payload of every provider.rmm_device.* event.
type RMMDeviceEvent struct {
	TargetID   string `json:"target_id"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	OrgID      string `json:"org_id,omitempty"`
	Present    bool   `json:"present,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	AgentMatch string `json:"agent_match,omitempty"`
	Health     string `json:"health,omitempty"`
	Action     string `json:"action,omitempty"`
	By         string `json:"by,omitempty"`
	// Request is the action_requested event an outcome answers.
	Request string `json:"request,omitempty"`
	OK      bool   `json:"ok,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ValidateRMMDeviceEvent checks a provider.rmm_device.* payload.
func ValidateRMMDeviceEvent(eventType string, p RMMDeviceEvent) error {
	if !billingTargetIDPattern.MatchString(p.TargetID) {
		return fmt.Errorf("an RMM device names a valid target, not %q", p.TargetID)
	}
	if strings.TrimSpace(p.DeviceID) == "" || len(p.DeviceID) > 128 {
		return fmt.Errorf("an RMM device names its device ID")
	}
	if len(p.DeviceName) > 255 || len(p.OrgID) > 128 || len(p.AgentID) > 64 || len(p.Health) > 255 || len(p.By) > 320 || len(p.Reason) > 2000 {
		return fmt.Errorf("an RMM device field is too long")
	}
	switch p.AgentMatch {
	case "", "installed", "hostname":
	default:
		return fmt.Errorf("unknown RMM agent match %q", p.AgentMatch)
	}
	switch eventType {
	case EventRMMDeviceObserved:
		if (p.AgentID == "") != (p.AgentMatch == "") {
			return fmt.Errorf("a mapped RMM device names its agent and how it matched")
		}
	case EventRMMDeviceActionRequested, EventRMMDeviceActionRecorded:
		switch p.Action {
		case "install", "upgrade", "remove":
		default:
			return fmt.Errorf("unknown RMM agent action %q", p.Action)
		}
		if eventType == EventRMMDeviceActionRecorded && (strings.TrimSpace(p.Request) == "" || len(p.Request) > 64) {
			return fmt.Errorf("an RMM agent action's outcome names its request")
		}
		if eventType == EventRMMDeviceActionRecorded && !p.OK && strings.TrimSpace(p.Reason) == "" {
			return fmt.Errorf("a failed RMM agent action says why")
		}
	default:
		return fmt.Errorf("unknown RMM device event %q", eventType)
	}
	return nil
}

func (p *Projector) applyRMMDeviceTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	var kind string
	switch e.Type {
	case EventRMMDeviceObserved:
		kind = "observed"
	case EventRMMDeviceActionRequested:
		kind = "action_requested"
	case EventRMMDeviceActionRecorded:
		kind = "action_recorded"
	default:
		return false, nil
	}
	var d RMMDeviceEvent
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidateRMMDeviceEvent(e.Type, d); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyRMMDeviceTx(ctx, tx, store.RMMDeviceChange{Kind: kind, TenantID: e.TenantID, TargetID: d.TargetID,
		DeviceID: d.DeviceID, DeviceName: d.DeviceName, OrgID: d.OrgID, Present: d.Present, AgentID: d.AgentID, AgentMatch: d.AgentMatch,
		Health: d.Health, Action: d.Action, By: d.By, EventID: e.ID, Request: d.Request, OK: d.OK, Reason: d.Reason, At: e.Time}, e.Sequence)
}
