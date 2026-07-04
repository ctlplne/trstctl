// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

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
	payload, err := json.Marshal(projections.ComplianceReportScheduleUpserted{
		ID: id, Framework: in.Framework, Name: in.Name, ReportType: in.ReportType,
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled,
		Delivery: delivery, RecipientRef: in.RecipientRef,
	})
	if err != nil {
		return store.ComplianceReportSchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventComplianceReportScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.ComplianceReportSchedule{}, err
	}
	return store.ComplianceReportSchedule{
		ID: id, TenantID: tenantID, Framework: in.Framework, Name: in.Name,
		ReportType: in.ReportType, IntervalSeconds: in.IntervalSeconds,
		Enabled: in.Enabled, Delivery: delivery, RecipientRef: in.RecipientRef,
		NextRunAt: ev.Time.Add(time.Duration(in.IntervalSeconds) * time.Second),
		CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}
