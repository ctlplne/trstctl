// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// RMM device agent actions and their states (MSP-9).
const (
	RMMActionRequested = "requested"
	RMMActionDone      = "done"
	RMMActionFailed    = "failed"
)

// RMMDevice is one device an RMM lists under a customer's organization, the
// agent it maps to, the health last reported back, and the agent action last
// requested through the RMM.
type RMMDevice struct {
	TenantID      string
	TargetID      string
	DeviceID      string
	DeviceName    string
	OrgID         string
	Present       bool
	AgentID       string
	AgentMatch    string
	Health        string
	Action        string
	ActionStatus  string
	ActionReason  string
	ActionBy      string
	ActionEventID string
	EventSequence uint64
	UpdatedAt     time.Time
}

// RMMDeviceChange is one projected device event.
type RMMDeviceChange struct {
	Kind     string // observed | action_requested | action_recorded
	TenantID string
	TargetID string
	DeviceID string
	// observed
	DeviceName string
	OrgID      string
	Present    bool
	AgentID    string
	AgentMatch string
	Health     string
	// actions: EventID is the request's own event (action_requested);
	// Request is the request an outcome answers (action_recorded).
	Action  string
	By      string
	EventID string
	Request string
	OK      bool
	Reason  string
	At      time.Time
}

// ApplyRMMDeviceTx projects one device event. An observation replaces the
// device's observed fields and keeps its action; a request sets the action
// in flight and names itself; an outcome applies only to the request it
// answers while that request is still in flight.
func (s *Store) ApplyRMMDeviceTx(ctx context.Context, tx pgx.Tx, c RMMDeviceChange, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return errors.New("store: RMM device event sequence is out of range")
	}
	seq := int64(sequence) // #nosec G115 -- bounded by the check above (CWE-190)
	at := c.At.UTC()
	switch c.Kind {
	case "observed":
		_, err := tx.Exec(ctx, `INSERT INTO provider_rmm_devices (tenant_id, target_id, device_id, device_name, org_id, present, agent_id,
			agent_match, health, event_sequence, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, target_id, device_id) DO UPDATE SET device_name = EXCLUDED.device_name, org_id = EXCLUDED.org_id,
			  present = EXCLUDED.present, agent_id = EXCLUDED.agent_id, agent_match = EXCLUDED.agent_match, health = EXCLUDED.health,
			  event_sequence = EXCLUDED.event_sequence, updated_at = EXCLUDED.updated_at
			WHERE provider_rmm_devices.event_sequence < EXCLUDED.event_sequence`,
			c.TenantID, c.TargetID, c.DeviceID, c.DeviceName, c.OrgID, c.Present, c.AgentID, c.AgentMatch, c.Health, seq, at)
		return err
	case "action_requested":
		_, err := tx.Exec(ctx, `UPDATE provider_rmm_devices SET action = $4, action_status = 'requested', action_reason = '',
			action_by = $5, action_event_id = $8, event_sequence = $6, updated_at = $7
			WHERE tenant_id = $1 AND target_id = $2 AND device_id = $3 AND event_sequence < $6`,
			c.TenantID, c.TargetID, c.DeviceID, c.Action, c.By, seq, at, c.EventID)
		return err
	case "action_recorded":
		status := RMMActionDone
		if !c.OK {
			status = RMMActionFailed
		}
		_, err := tx.Exec(ctx, `UPDATE provider_rmm_devices SET action_status = $5, action_reason = $6, event_sequence = $7, updated_at = $8
			WHERE tenant_id = $1 AND target_id = $2 AND device_id = $3 AND action = $4 AND action_status = 'requested'
			  AND action_event_id = $9 AND event_sequence < $7`,
			c.TenantID, c.TargetID, c.DeviceID, c.Action, status, c.Reason, seq, at, c.Request)
		return err
	default:
		return fmt.Errorf("store: unknown RMM device change %q", c.Kind)
	}
}

const rmmDeviceColumns = `tenant_id::text, target_id, device_id, device_name, org_id, present, agent_id, agent_match, health, action,
	action_status, action_reason, action_by, action_event_id, event_sequence, updated_at`

func scanRMMDevice(row interface{ Scan(...any) error }) (RMMDevice, error) {
	var d RMMDevice
	var seq int64
	if err := row.Scan(&d.TenantID, &d.TargetID, &d.DeviceID, &d.DeviceName, &d.OrgID, &d.Present, &d.AgentID, &d.AgentMatch, &d.Health,
		&d.Action, &d.ActionStatus, &d.ActionReason, &d.ActionBy, &d.ActionEventID, &seq, &d.UpdatedAt); err != nil {
		return RMMDevice{}, err
	}
	if seq > 0 {
		d.EventSequence = uint64(seq)
	}
	d.UpdatedAt = d.UpdatedAt.UTC()
	return d, nil
}

// RMMDevicesTx reads a customer's devices in one target inside a command's
// tenant transaction.
func RMMDevicesTx(ctx context.Context, tx pgx.Tx, tenantID, targetID string) ([]RMMDevice, error) {
	rows, err := tx.Query(ctx, `SELECT `+rmmDeviceColumns+` FROM provider_rmm_devices WHERE tenant_id = $1 AND target_id = $2
		ORDER BY device_id LIMIT 5000`, tenantID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RMMDevice
	for rows.Next() {
		d, err := scanRMMDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RMMDeviceForTx reads one device inside a command's tenant transaction,
// locking its row.
func RMMDeviceForTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, deviceID string) (RMMDevice, bool, error) {
	d, err := scanRMMDevice(tx.QueryRow(ctx, `SELECT `+rmmDeviceColumns+` FROM provider_rmm_devices
		WHERE tenant_id = $1 AND target_id = $2 AND device_id = $3 FOR UPDATE`, tenantID, targetID, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return RMMDevice{}, false, nil
	}
	return d, err == nil, err
}

// RMMDevices lists a customer's devices across its RMM targets.
func (s *Store) RMMDevices(ctx context.Context, tenantID string, limit int) ([]RMMDevice, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	var out []RMMDevice
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+rmmDeviceColumns+` FROM provider_rmm_devices WHERE tenant_id = $1
			ORDER BY present DESC, target_id, device_name, device_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanRMMDevice(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// RMMDeviceFor reads one device.
func (s *Store) RMMDeviceFor(ctx context.Context, tenantID, targetID, deviceID string) (RMMDevice, bool, error) {
	var out RMMDevice
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		d, err := scanRMMDevice(tx.QueryRow(ctx, `SELECT `+rmmDeviceColumns+` FROM provider_rmm_devices
			WHERE tenant_id = $1 AND target_id = $2 AND device_id = $3`, tenantID, targetID, deviceID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, found = d, true
		return nil
	})
	return out, found, err
}

// RMMAgent is what device matching and health need of an agent.
type RMMAgent struct {
	ID         string
	Name       string
	Status     string
	Version    string
	LastSeenAt *time.Time
}

// AgentsForRMM lists a customer's agents, for matching its RMM devices.
func (s *Store) AgentsForRMM(ctx context.Context, tenantID string) ([]RMMAgent, error) {
	var out []RMMAgent
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name, status, version, last_seen_at FROM agents WHERE tenant_id = $1 ORDER BY name, id LIMIT 20000`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a RMMAgent
			if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.Version, &a.LastSeenAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
