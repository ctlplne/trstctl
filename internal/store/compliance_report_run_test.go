// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A report receipt is a projection of an immutable event. It must keep the
// signed bytes for an auditor, advance only its own due edge, and never cross
// into another tenant's RLS partition.
func TestComplianceReportRunProjectionRetainsArtifactAndAdvancesExactDueEdge(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const scheduleID = "a81ea6c6-7c8d-4ac9-861a-19f590f7e100"
	const runID = "cc2ac3b9-3a08-4432-9a8c-1053fa34ec01"
	due := time.Date(2026, 10, 4, 7, 48, 42, 0, time.UTC)
	scheduled := store.ComplianceReportSchedule{
		ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "hourly pack",
		ReportType: "framework_evidence_pack", IntervalSeconds: 3600,
		Enabled: true, Delivery: "audit_export", NextRunAt: due,
		CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, scheduled)
	}); err != nil {
		t.Fatal(err)
	}
	completed := due.Add(25 * time.Minute)
	run := store.ComplianceReportRun{
		ID: runID, TenantID: tenantA, ScheduleID: scheduleID,
		DueAt: due, CompletedAt: completed, Framework: "soc2",
		ReportType: "framework_evidence_pack", Status: "completed", Attempt: 1, EventSequence: 10,
		CreatedAt: due, UpdatedAt: completed,
	}
	run.ArtifactDigest = crypto.SHA256Hex([]byte(`{"signed_export":{"signature":"AQ=="}}`))
	run.ArtifactRef = reportArtifactRef(run)
	for i := 0; i < 2; i++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyComplianceReportRunTx(ctx, tx, run)
		}); err != nil {
			t.Fatalf("project/replay run %d: %v", i, err)
		}
	}
	got, err := s.GetComplianceReportRun(ctx, tenantA, runID)
	if err != nil || got.Status != "completed" || got.ArtifactDigest != run.ArtifactDigest ||
		got.ArtifactRef != run.ArtifactRef {
		t.Fatalf("retained report run = %+v, err = %v", got, err)
	}
	updated, err := s.GetComplianceReportSchedule(ctx, tenantA, scheduleID)
	if err != nil || !updated.NextRunAt.Equal(completed.Add(time.Hour)) {
		t.Fatalf("next due after completed run = %+v, err = %v", updated, err)
	}
	if _, err := s.GetComplianceReportRun(ctx, tenantB, runID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant run read = %v, want no rows", err)
	}
	if _, err := s.GetComplianceReportRun(ctx, tenantA, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown run read = %v, want no rows", err)
	}
}

func TestComplianceReportRunProjectionRejectsCollisionAndDoesNotResumePausedSchedule(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const scheduleID = "a81ea6c6-7c8d-4ac9-861a-19f590f7e101"
	const runID = "cc2ac3b9-3a08-4432-9a8c-1053fa34ec02"
	due := time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)
	sched := store.ComplianceReportSchedule{
		ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "paused pack",
		ReportType: "framework_evidence_pack", IntervalSeconds: 3600,
		Enabled: false, Delivery: "audit_export", NextRunAt: due,
		CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Minute),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, sched)
	}); err != nil {
		t.Fatal(err)
	}
	run := store.ComplianceReportRun{
		ID: runID, TenantID: tenantA, ScheduleID: scheduleID, DueAt: due,
		Framework: "soc2", ReportType: "framework_evidence_pack", Status: "completed", Attempt: 1,
		EventSequence: 11, CreatedAt: due, UpdatedAt: due.Add(time.Minute), CompletedAt: due.Add(time.Minute),
	}
	run.ArtifactDigest = crypto.SHA256Hex([]byte(`{"signed_export":{"signature":"AQ=="}}`))
	run.ArtifactRef = reportArtifactRef(run)
	apply := func(in store.ComplianceReportRun) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyComplianceReportRunTx(ctx, tx, in) })
	}
	if err := apply(run); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetComplianceReportSchedule(ctx, tenantA, scheduleID)
	if err != nil || !got.NextRunAt.Equal(due) || got.Enabled {
		t.Fatalf("late completion resumed or advanced paused schedule: %+v, %v", got, err)
	}
	changed := run
	changed.ArtifactDigest = crypto.SHA256Hex([]byte(`{"signed_export":"different"}`))
	changed.ArtifactRef = reportArtifactRef(changed)
	if err := apply(changed); err == nil {
		t.Fatal("same event sequence replaced immutable signed artifact")
	}
	changed = run
	changed.ID = "cc2ac3b9-3a08-4432-9a8c-1053fa34ec03"
	changed.EventSequence = 12
	if err := apply(changed); err == nil {
		t.Fatal("second run ID claimed the same schedule due edge")
	}
}

func TestComplianceReportDueSelectionRespectsTenantRetryAndTerminalState(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	ids := []string{
		"ea0f4e18-8654-4bef-8e8c-c56a75ca0101",
		"ea0f4e18-8654-4bef-8e8c-c56a75ca0102",
		"ea0f4e18-8654-4bef-8e8c-c56a75ca0103",
		"ea0f4e18-8654-4bef-8e8c-c56a75ca0104",
	}
	for i, id := range ids {
		sched := store.ComplianceReportSchedule{
			ID: id, TenantID: tenantA, Framework: "soc2", Name: "due-select-" + id,
			ReportType: "framework_evidence_pack", IntervalSeconds: 3600,
			Enabled: true, Delivery: "audit_export", NextRunAt: now.Add(-time.Duration(4-i) * time.Minute),
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, sched)
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, status := range []string{"retrying", "failed", "queued"} {
		schedID := ids[i+1]
		run := store.ComplianceReportRun{
			ID: []string{
				"dc1d6b87-ce5d-4ae7-b05f-f32af3e90102",
				"dc1d6b87-ce5d-4ae7-b05f-f32af3e90103",
				"dc1d6b87-ce5d-4ae7-b05f-f32af3e90104",
			}[i],
			TenantID: tenantA, ScheduleID: schedID,
			DueAt: now.Add(-time.Duration(3-i) * time.Minute), Framework: "soc2",
			ReportType: "framework_evidence_pack", Status: status,
			EventSequence: uint64(20 + i), CreatedAt: now.Add(-time.Hour),
			UpdatedAt: now.Add(-2 * time.Minute),
		}
		if status != "queued" {
			run.Attempt = 1
			run.ErrorCode = "signer_unavailable"
		}
		if status == "retrying" {
			run.NextAttemptAt = now.Add(-time.Second)
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyComplianceReportRunTx(ctx, tx, run)
		}); err != nil {
			t.Fatal(err)
		}
	}
	tenants, err := s.TenantsWithEnabledComplianceReportSchedules(ctx)
	if err != nil || len(tenants) != 1 || tenants[0] != tenantA {
		t.Fatalf("schedule tenant inventory = %v, %v", tenants, err)
	}
	due, err := s.ComplianceReportSchedulesDue(ctx, tenantA, now, 100)
	if err != nil || len(due) != 2 || due[0].ID != ids[0] || due[1].ID != ids[1] {
		t.Fatalf("due schedules = %+v, %v", due, err)
	}
	foreign, err := s.ComplianceReportSchedulesDue(ctx, tenantB, now, 100)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign due schedules = %+v, %v", foreign, err)
	}
}

func TestComplianceReportFailedRunRequiresExplicitRequeueAndBoundsEachRetryCycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const scheduleID = "ea0f4e18-8654-4bef-8e8c-c56a75ca0301"
	const runID = "dc1d6b87-ce5d-4ae7-b05f-f32af3e90301"
	now := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	due := now.Add(-time.Hour)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, store.ComplianceReportSchedule{
			ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "retry test",
			ReportType: "framework_evidence_pack", IntervalSeconds: 3600,
			Enabled: true, Delivery: "audit_export", NextRunAt: due,
			CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	run := store.ComplianceReportRun{
		ID: runID, TenantID: tenantA, ScheduleID: scheduleID, DueAt: due,
		Framework: "soc2", ReportType: "framework_evidence_pack", Status: "failed",
		Attempt: 5, ErrorCode: "signer_unavailable", EventSequence: 20,
		CreatedAt: due, UpdatedAt: now.Add(-time.Minute),
	}
	apply := func(in store.ComplianceReportRun) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyComplianceReportRunTx(ctx, tx, in) })
	}
	if err := apply(run); err != nil {
		t.Fatal(err)
	}
	if dueRows, err := s.ComplianceReportSchedulesDue(ctx, tenantA, now, 10); err != nil || len(dueRows) != 0 {
		t.Fatalf("dead-lettered run auto-resumed: %+v, %v", dueRows, err)
	}
	invalid := run
	invalid.Status, invalid.Attempt, invalid.NextAttemptAt = "retrying", 0, now
	invalid.EventSequence++
	invalid.ErrorCode = ""
	if err := apply(invalid); err == nil {
		t.Fatal("same generation bypassed the terminal retry budget")
	}
	requeued := invalid
	requeued.RetryGeneration = 1
	if err := apply(requeued); err != nil {
		t.Fatalf("explicit requeue: %v", err)
	}
	if dueRows, err := s.ComplianceReportSchedulesDue(ctx, tenantA, now, 10); err != nil || len(dueRows) != 1 || dueRows[0].ID != scheduleID {
		t.Fatalf("explicit requeue not due: %+v, %v", dueRows, err)
	}
	replayed, err := s.GetComplianceReportRunByDue(ctx, tenantA, scheduleID, due)
	if err != nil || replayed.RetryGeneration != 1 || replayed.Attempt != 0 || replayed.Status != "retrying" {
		t.Fatalf("requeue receipt = %+v, %v", replayed, err)
	}
	if err := apply(requeued); err != nil {
		t.Fatalf("requeue event replay: %v", err)
	}
	failedAgain := requeued
	failedAgain.Status, failedAgain.Attempt, failedAgain.ErrorCode = "failed", 1, "signer_unavailable"
	failedAgain.NextAttemptAt = time.Time{}
	failedAgain.EventSequence++
	if err := apply(failedAgain); err != nil {
		t.Fatalf("failure after requeue: %v", err)
	}
	if dueRows, err := s.ComplianceReportSchedulesDue(ctx, tenantA, now, 10); err != nil || len(dueRows) != 0 {
		t.Fatalf("new dead letter auto-resumed: %+v, %v", dueRows, err)
	}
}

func TestComplianceReportArchiveReferenceSurvivesSnapshotRestore(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const scheduleID = "ea0f4e18-8654-4bef-8e8c-c56a75ca0201"
	const runID = "dc1d6b87-ce5d-4ae7-b05f-f32af3e90201"
	due := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	digest := crypto.SHA256Hex([]byte(`{"signed_export":{"signature":"AQ=="}}`))
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, store.ComplianceReportSchedule{
			ID: scheduleID, TenantID: tenantA, Framework: "soc2", Name: "snapshot pack",
			ReportType: "framework_evidence_pack", IntervalSeconds: 3600, Enabled: true,
			Delivery: "audit_export", NextRunAt: due,
			CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
		}); err != nil {
			return err
		}
		return s.ApplyComplianceReportRunTx(ctx, tx, store.ComplianceReportRun{
			ID: runID, TenantID: tenantA, ScheduleID: scheduleID, DueAt: due,
			Framework: "soc2", ReportType: "framework_evidence_pack", Status: "completed", Attempt: 1,
			ArtifactRef: fmt.Sprintf("reports/%s/%s-%s.json", tenantA, runID, digest), ArtifactDigest: digest,
			CompletedAt: due.Add(time.Minute), EventSequence: 17,
			CreatedAt: due, UpdatedAt: due.Add(time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	if count, err := s.WriteReadModelSnapshots(ctx); err != nil || count != 2 {
		t.Fatalf("capture report run = %d, %v", count, err)
	}
	if err := s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		_, err := s.RestoreSnapshotsTx(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("restore report run snapshot: %v", err)
	}
	got, err := s.GetComplianceReportRun(ctx, tenantA, runID)
	if err != nil || got.ArtifactRef != fmt.Sprintf("reports/%s/%s-%s.json", tenantA, runID, digest) ||
		got.ArtifactDigest != digest {
		t.Fatalf("restored archive receipt = %+v, %v", got, err)
	}
	if _, err := s.GetComplianceReportRun(ctx, tenantB, runID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("neighbor read after restore = %v", err)
	}
}

func reportArtifactRef(run store.ComplianceReportRun) string {
	return fmt.Sprintf("reports/%s/%s-%s.json", run.TenantID, run.ID, run.ArtifactDigest)
}
