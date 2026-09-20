// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// MDMDeviceCorrelation joins an MDM device record to a SCEP transaction (I5).
//
// A correlation, not a copy of the MDM: it holds the identifiers needed to join
// and the last thing the MDM said. Duplicating device inventory would create a
// second, staler source of truth about devices that somebody would eventually
// trust over the MDM itself.
type MDMDeviceCorrelation struct {
	ID            string
	TenantID      string
	MDM           string
	MDMDeviceID   string
	DeviceName    string
	SerialNumber  string
	TransactionID string
	IdentityID    string
	// InstallState is 'ok' | 'failed' | 'unknown'. Unknown is NOT failed: an MDM
	// we could not reach tells us nothing about the device.
	InstallState  string
	InstallDetail string
	ObservedAt    *time.Time
	UpdatedAt     time.Time
}

const mdmCorrelationCols = `id::text, tenant_id::text, mdm, mdm_device_id, device_name,
	serial_number, transaction_id, coalesce(identity_id::text, ''), install_state,
	install_detail, observed_at, updated_at`

func scanMDMCorrelation(row pgx.Row) (MDMDeviceCorrelation, error) {
	var c MDMDeviceCorrelation
	err := row.Scan(&c.ID, &c.TenantID, &c.MDM, &c.MDMDeviceID, &c.DeviceName, &c.SerialNumber,
		&c.TransactionID, &c.IdentityID, &c.InstallState, &c.InstallDetail, &c.ObservedAt, &c.UpdatedAt)
	return c, err
}

// ListMDMDeviceCorrelations returns the tenant's device correlations.
func (s *Store) ListMDMDeviceCorrelations(ctx context.Context, tenantID, mdm string, limit int) ([]MDMDeviceCorrelation, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []MDMDeviceCorrelation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+mdmCorrelationCols+` FROM mdm_device_correlations
			  WHERE tenant_id = $1 AND ($2 = '' OR mdm = $2)
			  ORDER BY updated_at DESC LIMIT $3`, tenantID, mdm, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanMDMCorrelation(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// GetMDMDeviceCorrelation loads one device's correlation by the MDM's own id —
// the identifier an admin can paste from their MDM console, which is the whole
// point of correlating.
func (s *Store) GetMDMDeviceCorrelation(ctx context.Context, tenantID, mdm, mdmDeviceID string) (MDMDeviceCorrelation, error) {
	var out MDMDeviceCorrelation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanMDMCorrelation(tx.QueryRow(ctx,
			`SELECT `+mdmCorrelationCols+` FROM mdm_device_correlations
			  WHERE tenant_id = $1 AND mdm = $2 AND mdm_device_id = $3
			  ORDER BY updated_at DESC LIMIT 1`, tenantID, mdm, mdmDeviceID))
		return err
	})
	return out, err
}

// ApplyMDMDeviceCorrelatedTx projects an mdm.device.correlated event.
//
// A device that re-enrolls gets a NEW row (the unique key includes the
// transaction), so a failed enrollment stays visible after a successful retry.
// That history is what shows an operator a device which keeps failing.
func (s *Store) ApplyMDMDeviceCorrelatedTx(ctx context.Context, tx pgx.Tx, c MDMDeviceCorrelation) error {
	var identity any
	if c.IdentityID != "" {
		identity = c.IdentityID
	}
	if err := lockUpsertArbiterTx(ctx, tx, "mdm_device_correlations", c.TenantID, c.MDM, c.MDMDeviceID, c.TransactionID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO mdm_device_correlations
		   (tenant_id, mdm, mdm_device_id, device_name, serial_number, transaction_id,
		    identity_id, install_state, install_detail, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::uuid, $8, $9, $10)
		 ON CONFLICT (tenant_id, mdm, mdm_device_id, transaction_id) DO UPDATE SET
		   device_name = EXCLUDED.device_name, serial_number = EXCLUDED.serial_number,
		   identity_id = coalesce(EXCLUDED.identity_id, mdm_device_correlations.identity_id),
		   install_state = EXCLUDED.install_state, install_detail = EXCLUDED.install_detail,
		   observed_at = EXCLUDED.observed_at, updated_at = now()`,
		c.TenantID, c.MDM, c.MDMDeviceID, c.DeviceName, c.SerialNumber, c.TransactionID,
		identity, c.InstallState, c.InstallDetail, c.ObservedAt)
	return err
}

// MDMPollSchedule is a tenant's standing instruction to re-read one MDM (I5).
type MDMPollSchedule struct {
	TenantID string
	MDM      string
	BaseURL  string
	TokenRef string
	// Filter is Intune's $filter or Jamf's section selector, encoded as a
	// query parameter by the endpoint builders — never a path segment.
	Filter          string
	IntervalSeconds int
	Enabled         bool
	// AllowPrivateEndpoint + PrivateEgressCIDRs gate a control-plane poll of a
	// private MDM (an on-prem Jamf). The caller needs egress:private to set
	// it, and the CIDRs bound exactly which private ranges the poll may dial —
	// same rule as discovery's cloud sources. Relay execution needs neither:
	// the relay is already inside.
	AllowPrivateEndpoint bool
	PrivateEgressCIDRs   []string
	// Execution is "" / "control_plane" for the control plane's own read, or
	// "relay" to dispatch an mdm.sync job a network relay claims (an on-prem
	// Jamf behind a firewall is exactly the CMDB's reachability shape).
	Execution string
	// RenewalWindowDays overrides the standard renewal window the offline
	// check uses. Zero means unset: the documented standard applies.
	RenewalWindowDays int
	LastRunAt         *time.Time
	LastError         string
}

// GetMDMPollSchedule returns one (tenant, mdm) schedule.
func (s *Store) GetMDMPollSchedule(ctx context.Context, tenantID, mdm string) (MDMPollSchedule, bool, error) {
	var out MDMPollSchedule
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, mdm, base_url, token_ref, filter, interval_seconds, enabled,
			        allow_private_endpoint, coalesce(private_egress_cidrs, '{}'),
			        coalesce(execution, ''), coalesce(renewal_window_days, 0), last_run_at, last_error
			   FROM mdm_poll_schedules WHERE tenant_id = $1 AND mdm = $2`, tenantID, mdm)
		switch err := row.Scan(&out.TenantID, &out.MDM, &out.BaseURL, &out.TokenRef, &out.Filter,
			&out.IntervalSeconds, &out.Enabled, &out.AllowPrivateEndpoint, &out.PrivateEgressCIDRs,
			&out.Execution, &out.RenewalWindowDays,
			&out.LastRunAt, &out.LastError); {
		case err == nil:
			found = true
			return nil
		case err.Error() == pgx.ErrNoRows.Error():
			return nil
		default:
			return err
		}
	})
	return out, found, err
}

// ListMDMPollSchedules returns the tenant's schedules for both MDMs.
func (s *Store) ListMDMPollSchedules(ctx context.Context, tenantID string) ([]MDMPollSchedule, error) {
	var out []MDMPollSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, mdm, base_url, token_ref, filter, interval_seconds, enabled,
			        allow_private_endpoint, coalesce(private_egress_cidrs, '{}'),
			        coalesce(execution, ''), coalesce(renewal_window_days, 0), last_run_at, last_error
			   FROM mdm_poll_schedules WHERE tenant_id = $1 ORDER BY mdm`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sch MDMPollSchedule
			if err := rows.Scan(&sch.TenantID, &sch.MDM, &sch.BaseURL, &sch.TokenRef, &sch.Filter,
				&sch.IntervalSeconds, &sch.Enabled, &sch.AllowPrivateEndpoint, &sch.PrivateEgressCIDRs,
				&sch.Execution, &sch.RenewalWindowDays,
				&sch.LastRunAt, &sch.LastError); err != nil {
				return err
			}
			out = append(out, sch)
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithEnabledMDMPollSchedules enumerates tenants for the leader ticker.
func (s *Store) TenantsWithEnabledMDMPollSchedules(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants have an enabled MDM poll schedule so the leader-only scheduler can sweep each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM mdm_poll_schedules WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MDMPollSchedulesDue returns the tenant's schedules due at now.
func (s *Store) MDMPollSchedulesDue(ctx context.Context, tenantID string, now time.Time) ([]MDMPollSchedule, error) {
	all, err := s.ListMDMPollSchedules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var due []MDMPollSchedule
	for _, sch := range all {
		if !sch.Enabled || sch.IntervalSeconds <= 0 {
			continue
		}
		if sch.LastRunAt != nil && now.Sub(*sch.LastRunAt) < time.Duration(sch.IntervalSeconds)*time.Second {
			continue
		}
		due = append(due, sch)
	}
	return due, nil
}

// MarkMDMPollRun stamps the attempt, exactly like the CMDB scheduler: a failed
// poll retries next interval rather than hot-looping, and the error is SERVED
// so a poll failing for a week does not look like one with nothing to do.
func (s *Store) MarkMDMPollRun(ctx context.Context, tenantID, mdm string, at time.Time, runErr string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE mdm_poll_schedules SET last_run_at = $3, last_error = $4, updated_at = now()
			  WHERE tenant_id = $1 AND mdm = $2`, tenantID, mdm, at.UTC(), runErr)
		return err
	})
}

// ApplyMDMPollConfiguredTx projects mdm.poll.configured (I5). last_run_at and
// last_error are the scheduler's observations and are deliberately untouched.
func (s *Store) ApplyMDMPollConfiguredTx(ctx context.Context, tx pgx.Tx, tenantID string, in MDMPollSchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO mdm_poll_schedules (tenant_id, mdm, base_url, token_ref, filter, interval_seconds, enabled, allow_private_endpoint, private_egress_cidrs, execution, renewal_window_days)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, nullif($10, ''), nullif($11, 0))
		 ON CONFLICT (tenant_id, mdm) DO UPDATE SET
		   base_url = EXCLUDED.base_url, token_ref = EXCLUDED.token_ref,
		   filter = EXCLUDED.filter, interval_seconds = EXCLUDED.interval_seconds,
		   enabled = EXCLUDED.enabled,
		   allow_private_endpoint = EXCLUDED.allow_private_endpoint,
		   private_egress_cidrs = EXCLUDED.private_egress_cidrs,
		   execution = EXCLUDED.execution,
		   renewal_window_days = EXCLUDED.renewal_window_days, updated_at = now()`,
		tenantID, in.MDM, in.BaseURL, in.TokenRef, in.Filter, in.IntervalSeconds,
		in.Enabled, false, nil, "relay", in.RenewalWindowDays)
	return err
}

// IdentitySerialJoin maps an UPPERCASED device serial to the identity enrolled
// under that name (I5). The join is EXACT equality on the identity name — the
// Intune SCEP convention puts the device serial in the subject CN — because a
// looser match would invent correlations, and an invented correlation sends an
// operator to the wrong laptop.
type IdentitySerialJoin struct {
	IdentityID string
	NotAfter   *time.Time
}

// IdentitiesBySerial returns the serial->identity join set for correlation.
func (s *Store) IdentitiesBySerial(ctx context.Context, tenantID string) (map[string]IdentitySerialJoin, error) {
	out := map[string]IdentitySerialJoin{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT upper(trim(name)), id::text, not_after FROM identities
			  WHERE tenant_id = $1 AND trim(name) <> ''`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var serial, id string
			var notAfter *time.Time
			if err := rows.Scan(&serial, &id, &notAfter); err != nil {
				return err
			}
			out[serial] = IdentitySerialJoin{IdentityID: id, NotAfter: notAfter}
		}
		return rows.Err()
	})
	return out, err
}
