// SPDX-License-Identifier: LicenseRef-trstctl-EE

package misuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/store"
)

// M2-L2: the detection rules' thresholds are each tenant's policy. A tenant
// sets them through misuse.policy.set; the misuse_policies read model holds
// the newest, and a tenant that set none is detected with the defaults.

// EventPolicySet records a tenant's misuse detection thresholds.
const EventPolicySet = "misuse.policy.set"

// Policy is a tenant's misuse detection thresholds: a lease from a network
// the token has not used on NormalDays different days is new; an hour of at
// least BurstFloor secret reads and BurstFactor times the token's largest
// earlier hour in BurstLookbackDays days is a burst; at most HourlyAlertCap
// findings an hour alert.
type Policy struct {
	NormalDays        int `json:"normal_days"`
	BurstFloor        int `json:"burst_floor"`
	BurstFactor       int `json:"burst_factor"`
	BurstLookbackDays int `json:"burst_lookback_days"`
	HourlyAlertCap    int `json:"hourly_alert_cap"`
}

// DefaultPolicy is the policy of a tenant that set none.
func DefaultPolicy(hourlyCap int) Policy {
	if hourlyCap <= 0 {
		hourlyCap = defaultHourlyCap
	}
	return Policy{NormalDays: normalDays, BurstFloor: burstFloor, BurstFactor: burstFactor,
		BurstLookbackDays: int(burstLookback / (24 * time.Hour)), HourlyAlertCap: hourlyCap}
}

// Validate keeps each threshold in a range detection can use.
func (p Policy) Validate() error {
	switch {
	case p.NormalDays < 1 || p.NormalDays > 30:
		return errors.New("normal_days must be 1-30")
	case p.BurstFloor < 1 || p.BurstFloor > 100000:
		return errors.New("burst_floor must be 1-100000")
	case p.BurstFactor < 2 || p.BurstFactor > 100:
		return errors.New("burst_factor must be 2-100")
	case p.BurstLookbackDays < 1 || p.BurstLookbackDays > 90:
		return errors.New("burst_lookback_days must be 1-90")
	case p.HourlyAlertCap < 1 || p.HourlyAlertCap > 1000:
		return errors.New("hourly_alert_cap must be 1-1000")
	}
	return nil
}

// PolicyView is a tenant's policy as served; Custom is false when the
// defaults apply.
type PolicyView struct {
	Policy
	Custom    bool       `json:"custom"`
	SetBy     string     `json:"set_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// readPolicy reads a tenant's policy, or the defaults when it set none.
func readPolicy(ctx context.Context, st *store.Store, tenantID string, defaults Policy) (PolicyView, error) {
	view := PolicyView{Policy: defaults}
	err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var updated time.Time
		err := tx.QueryRow(ctx, `SELECT normal_days, burst_floor, burst_factor, burst_lookback_days, hourly_alert_cap, set_by, updated_at
			  FROM misuse_policies WHERE tenant_id = $1`, tenantID).
			Scan(&view.NormalDays, &view.BurstFloor, &view.BurstFactor, &view.BurstLookbackDays, &view.HourlyAlertCap, &view.SetBy, &updated)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		view.Custom, view.UpdatedAt = true, &updated
		return nil
	})
	return view, err
}

// applyPolicySetTx projects misuse.policy.set: the newest event wins, and a
// replayed one changes nothing.
func (p *Projection) applyPolicySetTx(ctx context.Context, tx pgx.Tx, ev eventspec.Event) error {
	var pol Policy
	if err := json.Unmarshal(ev.Data, &pol); err != nil {
		return fmt.Errorf("misuse: decode %s: %w", ev.Type, err)
	}
	if err := pol.Validate(); err != nil || ev.Sequence == 0 || ev.Sequence > math.MaxInt64 {
		return fmt.Errorf("misuse: %s payload is not a policy: %v", ev.Type, err)
	}
	setBy := ""
	if ev.Actor != nil {
		setBy = ev.Actor.Subject
	}
	if err := p.store.SetTenantGUCTx(ctx, tx, ev.TenantID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO misuse_policies (tenant_id, normal_days, burst_floor, burst_factor, burst_lookback_days, hourly_alert_cap,
		                             set_by, updated_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id) DO UPDATE SET normal_days = EXCLUDED.normal_days, burst_floor = EXCLUDED.burst_floor,
		    burst_factor = EXCLUDED.burst_factor, burst_lookback_days = EXCLUDED.burst_lookback_days,
		    hourly_alert_cap = EXCLUDED.hourly_alert_cap, set_by = EXCLUDED.set_by, updated_at = EXCLUDED.updated_at,
		    event_sequence = EXCLUDED.event_sequence
		  WHERE misuse_policies.event_sequence < EXCLUDED.event_sequence`,
		ev.TenantID, pol.NormalDays, pol.BurstFloor, pol.BurstFactor, pol.BurstLookbackDays, pol.HourlyAlertCap,
		setBy, ev.Time.UTC(), int64(ev.Sequence)) // #nosec G115 -- bounded by MaxInt64 above.
	return err
}

// PolicyStore reads and sets tenants' policies.
type PolicyStore struct {
	Store    *store.Store
	Log      *events.Log
	Defaults Policy
}

// Get returns a tenant's policy, or the defaults.
func (s PolicyStore) Get(ctx context.Context, tenantID string) (PolicyView, error) {
	return readPolicy(ctx, s.Store, tenantID, s.Defaults)
}

// Set records a tenant's policy and projects it in one tenant transaction
// (AN-2, AN-6); the caller's actor rides in ctx.
func (s PolicyStore) Set(ctx context.Context, tenantID string, pol Policy) (PolicyView, error) {
	if err := pol.Validate(); err != nil {
		return PolicyView{}, err
	}
	if s.Store == nil || s.Log == nil {
		return PolicyView{}, errors.New("misuse: setting a policy needs the store and the event log")
	}
	payload, err := json.Marshal(pol)
	if err != nil {
		return PolicyView{}, err
	}
	proj := NewProjection(s.Store)
	if err := s.Store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ev, err := s.Log.Append(ctx, events.Event{Type: EventPolicySet, TenantID: tenantID, Data: payload})
		if err != nil {
			return err
		}
		return proj.applyPolicySetTx(ctx, tx, ev)
	}); err != nil {
		return PolicyView{}, err
	}
	return s.Get(ctx, tenantID)
}
