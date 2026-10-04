// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestComplianceReportRunCommandRecoversRetainedAppendAndBindsDueEdge(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "report-tenant", CreatedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	const scheduleID = "20d28e4a-ec47-468a-adfa-a11a9ad2669b"
	due := now.Add(-time.Minute)
	schedule := store.ComplianceReportSchedule{
		ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "daily evidence",
		ReportType: "audit_summary", IntervalSeconds: 86400, Enabled: true,
		Delivery: "audit_export", NextRunAt: due, CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, schedule)
	}); err != nil {
		t.Fatal(err)
	}
	run := store.ComplianceReportRun{
		ID: orchestrator.ComplianceReportRunID(tenantA, scheduleID, due), TenantID: tenantA,
		ScheduleID: scheduleID, DueAt: due, Framework: schedule.Framework,
		ReportType: schedule.ReportType, Status: "queued", CreatedAt: now,
	}
	command := orchestrator.NewOrchestrator(log, st, nil)
	got, err := command.RecordComplianceReportRun(ctx, run)
	if err != nil || got.Status != "queued" || got.EventSequence == 0 {
		t.Fatalf("queue report run = %+v, %v", got, err)
	}
	firstSeq := got.EventSequence
	got, err = command.RecordComplianceReportRun(ctx, run)
	if err != nil || got.EventSequence != firstSeq {
		t.Fatalf("retry queued command minted another event: %+v, %v", got, err)
	}
	if _, err := st.GetComplianceReportRun(ctx, tenantB, run.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("other tenant read report receipt: %v", err)
	}
	// Model the crash gap: append succeeded, but SQL projection never committed.
	retry := run
	retry.Status = "retrying"
	retry.Attempt = 1
	retry.ErrorCode = "signer_unavailable"
	retry.NextAttemptAt = now.Add(time.Minute)
	eventID := orchestrator.ComplianceReportRunEventID(retry)
	payload, err := json.Marshal(projections.ComplianceReportRunRecorded{
		ID: retry.ID, ScheduleID: retry.ScheduleID, DueAt: retry.DueAt,
		Framework: retry.Framework, ReportType: retry.ReportType, Status: retry.Status,
		RetryGeneration: retry.RetryGeneration, Attempt: retry.Attempt,
		NextAttemptAt: retry.NextAttemptAt, ErrorCode: retry.ErrorCode,
		CreatedAt: retry.CreatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = log.Append(ctx, events.Event{
		ID: eventID, TenantID: tenantA, Type: projections.EventComplianceReportRunRecorded,
		SchemaVersion: 1,
		Data:          payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err = command.RecordComplianceReportRun(ctx, retry)
	if err != nil || got.Status != "retrying" || got.Attempt != 1 || !got.NextAttemptAt.Equal(retry.NextAttemptAt) {
		t.Fatalf("retained event did not repair projection: %+v, %v", got, err)
	}
	retained, found, err := log.EventByID(ctx, eventID)
	if err != nil || !found || got.EventSequence != retained.Sequence {
		t.Fatalf("report run did not use retained source event: %+v, %+v, %v", got, retained, err)
	}
	conflict := retry
	conflict.ErrorCode = "archive_unavailable"
	if _, err := command.RecordComplianceReportRun(ctx, conflict); err == nil {
		t.Fatal("same deterministic event identity accepted different failure metadata")
	}
}
