// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Scheduled report dispatch (A103). The archive stays the record of a signed
// report; a schedule may also announce each completed run on named
// notification channels and in one ServiceNow ticket. The completed run event
// carries the dispatch decision, and the notices and ticket are enqueued in
// the transaction that projects it, so a run is never completed without its
// announcements and never announced twice. Notices reference the archived
// report and its digest; the report body never leaves the archive this way.

var complianceReportTicketNamespace = uuid.MustParse("5b1d7c0e-7f3a-4f0e-9f53-2a6a3c9d8e41")

// ComplianceReportRunDispatchFor snapshots a schedule's dispatch for one
// completed run, or nil when the schedule announces nothing.
func ComplianceReportRunDispatchFor(schedule store.ComplianceReportSchedule) *store.ComplianceReportRunDispatch {
	if schedule.Dispatch.Empty() {
		return nil
	}
	out := &store.ComplianceReportRunDispatch{ScheduleName: schedule.Name}
	out.Channels = append([]string(nil), schedule.Dispatch.Channels...)
	if t := schedule.Dispatch.Ticket; t != nil {
		ticket := *t
		out.Ticket = &ticket
	}
	return out
}

// ComplianceReportDownloadPath is where an authorized operator downloads a
// run's exact signed bytes.
func ComplianceReportDownloadPath(runID string) string {
	return "/api/v1/compliance/report-runs/" + runID + "/artifact"
}

// enqueueComplianceReportDispatchTx queues one notice per named channel and
// the ticket for a completed run event. Keys derive from the run, so the
// projection command, a retained-event recovery and outbox reconciliation all
// converge on the same rows.
func (o *Orchestrator) enqueueComplianceReportDispatchTx(ctx context.Context, tx pgx.Tx, tenantID string, rec projections.ComplianceReportRunRecorded) error {
	if rec.Status != "completed" || rec.Dispatch == nil {
		return nil
	}
	if o.outbox == nil {
		return fmt.Errorf("orchestrator: report dispatch outbox is unavailable")
	}
	d := rec.Dispatch
	detail := fmt.Sprintf("The %s %s report due %s is signed and archived (SHA-256 %s). Download it with GET %s.",
		rec.Framework, rec.ReportType, rec.DueAt.UTC().Format("2006-01-02 15:04 UTC"), rec.ArtifactDigest, ComplianceReportDownloadPath(rec.ID))
	for _, channel := range d.Channels {
		alert := notify.Alert{
			Kind: notify.KindComplianceReportReady, TenantID: tenantID,
			OperationID: "compliance-report:" + rec.ID, Subject: d.ScheduleName, Detail: detail,
			Severity: notify.AlertSeverityInformational, TargetChannel: channel,
			Report: &notify.AlertReport{
				ScheduleID: rec.ScheduleID, ScheduleName: d.ScheduleName, RunID: rec.ID,
				Framework: rec.Framework, ReportType: rec.ReportType, DueAt: rec.DueAt.UTC(),
				ArtifactSHA256: rec.ArtifactDigest, DownloadPath: ComplianceReportDownloadPath(rec.ID),
			},
		}
		payload, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: notify.DestinationComplianceReport,
			IdempotencyKey: "compliance-report:" + rec.ID + ":" + channel, Payload: payload,
		}); err != nil {
			return err
		}
	}
	if t := d.Ticket; t != nil {
		payload, err := json.Marshal(ServiceNowTicketRequest{
			ID:               uuid.NewSHA1(complianceReportTicketNamespace, []byte(tenantID+"\x00"+rec.ID)).String(),
			InstanceURL:      t.InstanceURL,
			Table:            t.Table,
			TokenRef:         t.TokenRef,
			ShortDescription: "Scheduled report ready: " + d.ScheduleName,
			Description:      detail,
			Category:         "compliance",
			CorrelationID:    rec.ID,
			RequestedBy:      "system:compliance-report-scheduler",
		})
		if err != nil {
			return err
		}
		if _, err := o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: DestinationITSMServiceNow,
			IdempotencyKey: "compliance-report-ticket:" + rec.ID, Payload: payload,
		}); err != nil {
			return err
		}
	}
	return nil
}
