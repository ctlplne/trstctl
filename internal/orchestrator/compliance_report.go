// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// UpsertComplianceReportSchedule records a tenant reporting schedule as an
// immutable event. The relational schedule row is only the projection of that
// event, so rebuild/replay can reconstruct the reporting cadence.
func (o *Orchestrator) UpsertComplianceReportSchedule(ctx context.Context, tenantID string, in store.ComplianceReportSchedule) (store.ComplianceReportSchedule, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	delivery := in.Delivery
	if delivery == "" {
		delivery = "audit_export"
	}
	dispatch := in.Dispatch
	if dispatch.Empty() {
		dispatch = nil
	}
	payload, err := json.Marshal(projections.ComplianceReportScheduleUpserted{
		ID: id, Framework: in.Framework, Name: in.Name, ReportType: in.ReportType,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
		Delivery: delivery, RecipientRef: in.RecipientRef, Dispatch: dispatch,
	})
	if err != nil {
		return store.ComplianceReportSchedule{}, err
	}
	// LS-1: a name another schedule holds is refused before anything is
	// appended; the projection lock spans the check, the append and its
	// projection, for the API's create and update and the tenant baseline.
	var ev events.Event
	err = o.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		if err := o.store.EnsureTenantNameAvailable(ctx, "compliance_report_schedules", tenantID, id, in.Name); err != nil {
			return err
		}
		var err error
		ev, err = o.emit(ctx, projections.EventComplianceReportScheduleUpserted, tenantID, payload)
		return err
	})
	if err != nil {
		return store.ComplianceReportSchedule{}, err
	}
	createdAt := in.CreatedAt
	if createdAt.IsZero() {
		createdAt = ev.Time
	}
	return store.ComplianceReportSchedule{
		ID: id, TenantID: tenantID, Framework: in.Framework, Name: in.Name,
		ReportType: in.ReportType, IntervalSeconds: in.IntervalSeconds,
		Enabled: in.Enabled, Delivery: delivery, RecipientRef: in.RecipientRef, Dispatch: dispatch,
		NextRunAt: ev.Time.Add(time.Duration(in.IntervalSeconds) * time.Second), CreatedAt: createdAt, UpdatedAt: ev.Time,
	}, nil
}
