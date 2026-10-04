// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var complianceReportRunNamespace = uuid.MustParse("18163c72-d06d-4c04-943b-8e33b9289364")

// ComplianceReportRunID is the stable identity for one schedule due edge. A
// failover producer must address the same receipt, not create another report.
func ComplianceReportRunID(tenantID, scheduleID string, dueAt time.Time) string {
	return uuid.NewSHA1(complianceReportRunNamespace,
		[]byte("run\x00"+tenantID+"\x00"+scheduleID+"\x00"+dueAt.UTC().Format(time.RFC3339Nano))).String()
}

// ComplianceReportRunEventID identifies one queued, attempted or requeued
// transition. It deliberately excludes a process clock: JetStream's duplicate
// window is finite, and recovery must find the original retained event.
func ComplianceReportRunEventID(run store.ComplianceReportRun) string {
	return uuid.NewSHA1(complianceReportRunNamespace,
		[]byte(fmt.Sprintf("transition\x00%s\x00%d\x00%d\x00%s",
			run.ID, run.RetryGeneration, run.Attempt, run.Status))).String()
}

// RecordComplianceReportRun records only report metadata and an archive digest
// in the event log. It preflights the projection schema, finds a prior source
// event across JetStream's finite dedupe window, and completes a projection
// interrupted after append. The caller must hold the exact due-edge lock.
func (o *Orchestrator) RecordComplianceReportRun(ctx context.Context, run store.ComplianceReportRun) (store.ComplianceReportRun, error) {
	if o == nil || o.store == nil || o.log == nil || o.proj == nil {
		return store.ComplianceReportRun{}, errors.New("orchestrator: report run spine is not configured")
	}
	if run.ID != ComplianceReportRunID(run.TenantID, run.ScheduleID, run.DueAt) {
		return store.ComplianceReportRun{}, errors.New("orchestrator: report run does not match deterministic due edge")
	}
	preflight := run
	preflight.EventSequence = 1
	preflight.UpdatedAt = time.Now().UTC()
	if err := store.ValidateComplianceReportRun(preflight); err != nil {
		return store.ComplianceReportRun{}, err
	}
	payload, err := json.Marshal(projections.ComplianceReportRunRecorded{
		ID: run.ID, ScheduleID: run.ScheduleID, DueAt: run.DueAt,
		Framework: run.Framework, ReportType: run.ReportType,
		Status: run.Status, RetryGeneration: run.RetryGeneration, Attempt: run.Attempt,
		NextAttemptAt: run.NextAttemptAt, ErrorCode: run.ErrorCode,
		ArtifactRef: run.ArtifactRef, ArtifactDigest: run.ArtifactDigest,
		CompletedAt: run.CompletedAt, CreatedAt: run.CreatedAt,
	})
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	eventID := ComplianceReportRunEventID(run)
	retained, found, err := o.log.EventByID(ctx, eventID)
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	if found {
		var previous projections.ComplianceReportRunRecorded
		if retained.Type != projections.EventComplianceReportRunRecorded || retained.TenantID != run.TenantID ||
			json.Unmarshal(retained.Data, &previous) != nil ||
			previous.ID != run.ID || previous.ScheduleID != run.ScheduleID ||
			!previous.DueAt.Equal(run.DueAt) || previous.Framework != run.Framework ||
			previous.ReportType != run.ReportType || previous.Status != run.Status ||
			previous.RetryGeneration != run.RetryGeneration || previous.Attempt != run.Attempt ||
			!previous.NextAttemptAt.Equal(run.NextAttemptAt) || previous.ErrorCode != run.ErrorCode ||
			previous.ArtifactRef != run.ArtifactRef || previous.ArtifactDigest != run.ArtifactDigest ||
			!previous.CompletedAt.Equal(run.CompletedAt) || !previous.CreatedAt.Equal(run.CreatedAt) {
			return store.ComplianceReportRun{}, errors.New("orchestrator: retained report event identity conflicts with requested transition")
		}
		current, readErr := o.store.GetComplianceReportRun(ctx, run.TenantID, run.ID)
		if readErr == nil && current.EventSequence >= retained.Sequence {
			return current, nil
		}
		if readErr != nil && !errors.Is(readErr, pgx.ErrNoRows) {
			return store.ComplianceReportRun{}, readErr
		}
		err = o.withTenantCommand(ctx, run.TenantID, func(ctx context.Context, tx pgx.Tx) error {
			return o.proj.ApplyTx(ctx, tx, retained)
		})
	} else {
		_, err = o.emitPrepared(ctx, events.Event{
			ID: eventID, Type: projections.EventComplianceReportRunRecorded,
			TenantID: run.TenantID, SchemaVersion: 1, Data: payload,
		})
	}
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	return o.store.GetComplianceReportRun(ctx, run.TenantID, run.ID)
}
