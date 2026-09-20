// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
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
	NextRunAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
	_, err := tx.Exec(ctx,
		`INSERT INTO compliance_report_schedules
		        (id, tenant_id, framework, name, report_type, interval_seconds, enabled,
		         delivery, recipient_ref, next_run_at, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET framework = EXCLUDED.framework,
		          name = EXCLUDED.name,
		          report_type = EXCLUDED.report_type,
		          interval_seconds = EXCLUDED.interval_seconds,
		          enabled = EXCLUDED.enabled,
		          delivery = EXCLUDED.delivery,
		          recipient_ref = EXCLUDED.recipient_ref,
		          next_run_at = EXCLUDED.next_run_at,
		          updated_at = EXCLUDED.updated_at`,
		sched.ID, sched.TenantID, sched.Framework, sched.Name, sched.ReportType,
		sched.IntervalSeconds, sched.Enabled, sched.Delivery, sched.RecipientRef,
		sched.NextRunAt, sched.CreatedAt, sched.UpdatedAt)
	return err
}

// ListComplianceReportSchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListComplianceReportSchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]ComplianceReportSchedule, error) {
	var out []ComplianceReportSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, framework, name, report_type, interval_seconds,
			        enabled, delivery, recipient_ref, next_run_at, created_at, updated_at
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
			        enabled, delivery, recipient_ref, next_run_at, created_at, updated_at
			   FROM compliance_report_schedules
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
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
	return row.Scan(&sched.ID, &sched.TenantID, &sched.Framework, &sched.Name, &sched.ReportType,
		&sched.IntervalSeconds, &sched.Enabled, &sched.Delivery, &sched.RecipientRef,
		&sched.NextRunAt, &sched.CreatedAt, &sched.UpdatedAt)
}
