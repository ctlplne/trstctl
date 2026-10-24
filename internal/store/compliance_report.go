// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ComplianceReportSchedule is a tenant-owned scheduled report definition. It is
// projected from compliance.report_schedule.upserted events and stores only
// reporting metadata/references, never generated report bytes or delivery secrets.
type ComplianceReportSchedule struct {
	ID              string
	TenantID        string
	Framework       string
	Name            string
	ReportType      string
	IntervalSeconds int
	Enabled         bool
	Delivery        string
	RecipientRef    string
	// Dispatch announces each completed run beyond the archive (A103); nil
	// means archive only.
	Dispatch  *ComplianceReportDispatch
	NextRunAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ComplianceReportDispatch says where a completed scheduled report is
// announced (A103): notification channels by ID and at most one ServiceNow
// ticket. It never carries the report body or a credential value; the ticket
// names a credential reference the outbox worker resolves at egress.
type ComplianceReportDispatch struct {
	Channels []string                `json:"channels,omitempty"`
	Ticket   *ComplianceReportTicket `json:"ticket,omitempty"`
}

// ComplianceReportTicket is the ServiceNow ticket a completed run opens.
type ComplianceReportTicket struct {
	Provider    string `json:"provider"`
	InstanceURL string `json:"instance_url"`
	Table       string `json:"table"`
	TokenRef    string `json:"token_ref"`
}

// Empty reports whether the dispatch announces nothing.
func (d *ComplianceReportDispatch) Empty() bool {
	return d == nil || (len(d.Channels) == 0 && d.Ticket == nil)
}

// ComplianceReportRunDispatch is the immutable announcement decision a
// completed run carries: the schedule's name and dispatch at completion, so a
// later schedule edit cannot change what a past run announced.
type ComplianceReportRunDispatch struct {
	ScheduleName string                  `json:"schedule_name"`
	Channels     []string                `json:"channels,omitempty"`
	Ticket       *ComplianceReportTicket `json:"ticket,omitempty"`
	// TicketSkipped says why the schedule's ticket was not opened, such as an
	// operator having withdrawn its ServiceNow binding since the schedule was
	// created.
	TicketSkipped string `json:"ticket_skipped,omitempty"`
}

func dispatchJSON(v any) (any, error) {
	switch d := v.(type) {
	case *ComplianceReportDispatch:
		if d.Empty() {
			return nil, nil
		}
	case *ComplianceReportRunDispatch:
		if d == nil {
			return nil, nil
		}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(raw), nil
}

// ComplianceInventoryCounts is the tenant-scoped inventory summarized by the
// compliance report API.
type ComplianceInventoryCounts struct {
	Certificates           int
	CryptoAssets           int
	DiscoverySchedules     int
	ReportSchedules        int
	EnabledReportSchedules int
	InventoryRows          int
}

// ApplyComplianceReportScheduleUpsertedTx projects a
// compliance.report_schedule.upserted event.
func (s *Store) ApplyComplianceReportScheduleUpsertedTx(ctx context.Context, tx pgx.Tx, sched ComplianceReportSchedule) error {
	if err := lockUpsertArbiterTx(ctx, tx, "compliance_report_schedules", sched.TenantID, sched.ID); err != nil {
		return err
	}
	dispatch, err := dispatchJSON(sched.Dispatch)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO compliance_report_schedules
		        (id, tenant_id, framework, name, report_type, interval_seconds, enabled,
		         delivery, recipient_ref, next_run_at, created_at, updated_at, dispatch)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET framework = EXCLUDED.framework,
		          name = EXCLUDED.name,
		          report_type = EXCLUDED.report_type,
		          interval_seconds = EXCLUDED.interval_seconds,
		          enabled = EXCLUDED.enabled,
		          delivery = EXCLUDED.delivery,
		          recipient_ref = EXCLUDED.recipient_ref,
		          next_run_at = EXCLUDED.next_run_at,
		          updated_at = EXCLUDED.updated_at,
		          dispatch = EXCLUDED.dispatch`,
		sched.ID, sched.TenantID, sched.Framework, sched.Name, sched.ReportType,
		sched.IntervalSeconds, sched.Enabled, sched.Delivery, sched.RecipientRef,
		sched.NextRunAt, sched.CreatedAt, sched.UpdatedAt, dispatch)
	return err
}

// ListComplianceReportSchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListComplianceReportSchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]ComplianceReportSchedule, error) {
	var out []ComplianceReportSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, framework, name, report_type, interval_seconds,
			        enabled, delivery, recipient_ref, next_run_at, created_at, updated_at, dispatch
			   FROM compliance_report_schedules
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched ComplianceReportSchedule
			if err := scanComplianceReportSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// GetComplianceReportSchedule loads one tenant-scoped schedule.
func (s *Store) GetComplianceReportSchedule(ctx context.Context, tenantID, id string) (ComplianceReportSchedule, error) {
	var out ComplianceReportSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanComplianceReportSchedule(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, framework, name, report_type, interval_seconds,
			        enabled, delivery, recipient_ref, next_run_at, created_at, updated_at, dispatch
			   FROM compliance_report_schedules
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

// TenantsWithEnabledComplianceReportSchedules is a system inventory of tenant
// IDs only. The scheduler then reads each due row inside that tenant's RLS
// context; no report definition or artifact crosses this system query.
func (s *Store) TenantsWithEnabledComplianceReportSchedules(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — leader-only cross-tenant scheduler enumeration returns tenant UUIDs only; exact definitions and artifacts are read under each tenant's forced RLS policy.
		`SELECT DISTINCT tenant_id::text FROM compliance_report_schedules WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// ComplianceReportSchedulesDue returns a bounded, tenant-scoped set. A failed
// run waits for explicit requeue; a retry waits for its persisted backoff. A
// queued run is recoverable after five minutes if a process died mid-attempt.
func (s *Store) ComplianceReportSchedulesDue(ctx context.Context, tenantID string, now time.Time, limit int) ([]ComplianceReportSchedule, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []ComplianceReportSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT s.id::text, s.tenant_id::text, s.framework, s.name, s.report_type,
			        s.interval_seconds, s.enabled, s.delivery, s.recipient_ref,
			        s.next_run_at, s.created_at, s.updated_at, s.dispatch
			   FROM compliance_report_schedules s
			   LEFT JOIN compliance_report_runs r
			     ON r.tenant_id = s.tenant_id AND r.schedule_id = s.id
			    AND r.due_at = s.next_run_at
			  WHERE s.tenant_id = $1 AND s.enabled AND s.next_run_at <= $2
			    AND (r.id IS NULL OR
			         (r.status = 'retrying' AND r.next_attempt_at <= $2) OR
			         (r.status = 'queued' AND r.updated_at <= $2::timestamptz - interval '5 minutes'))
			  ORDER BY s.next_run_at, s.id LIMIT $3`, tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched ComplianceReportSchedule
			if err := scanComplianceReportSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// ComplianceInventoryCounts returns the tenant-scoped inventory totals that feed
// the compliance/inventory report.
func (s *Store) ComplianceInventoryCounts(ctx context.Context, tenantID string) (ComplianceInventoryCounts, error) {
	var out ComplianceInventoryCounts
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			    (SELECT count(*)::integer FROM certificates WHERE tenant_id = $1),
			    (SELECT count(*)::integer FROM crypto_assets WHERE tenant_id = $1 AND is_active),
			    (SELECT count(*)::integer FROM discovery_schedules WHERE tenant_id = $1),
			    (SELECT count(*)::integer FROM compliance_report_schedules WHERE tenant_id = $1),
			    (SELECT count(*)::integer FROM compliance_report_schedules WHERE tenant_id = $1 AND enabled)`,
			tenantID).Scan(&out.Certificates, &out.CryptoAssets, &out.DiscoverySchedules,
			&out.ReportSchedules, &out.EnabledReportSchedules)
	})
	out.InventoryRows = out.Certificates + out.CryptoAssets + out.DiscoverySchedules + out.ReportSchedules
	return out, err
}

func scanComplianceReportSchedule(row rowScanner, sched *ComplianceReportSchedule) error {
	var dispatch []byte
	if err := row.Scan(&sched.ID, &sched.TenantID, &sched.Framework, &sched.Name, &sched.ReportType,
		&sched.IntervalSeconds, &sched.Enabled, &sched.Delivery, &sched.RecipientRef,
		&sched.NextRunAt, &sched.CreatedAt, &sched.UpdatedAt, &dispatch); err != nil {
		return err
	}
	sched.Dispatch = nil
	if len(dispatch) > 0 {
		var d ComplianceReportDispatch
		if err := json.Unmarshal(dispatch, &d); err != nil {
			return fmt.Errorf("store: decode report schedule dispatch: %w", err)
		}
		sched.Dispatch = &d
	}
	return nil
}
