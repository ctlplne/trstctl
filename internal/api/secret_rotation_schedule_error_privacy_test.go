// SPDX-License-Identifier: MPL-2.0

package api

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestSecretRotationScheduleDurableErrorsRejectProviderAndStoreText(t *testing.T) {
	const sensitive = "credential=super-secret subject=alice@example.test remote=vault/alice"

	system := secretRotationScheduleSystemErrorDetail(errors.New(sensitive))
	terminal := secretRotationScheduleTerminalErrorDetail(
		fmt.Errorf("%w: %s", errTerminalConnectorRotationDelivery, sensitive),
	)
	unknownAPI := secretRotationScheduleTerminalErrorDetail(errStatus(503, sensitive))
	deferred := secretRotationScheduleDeferredError{
		reason: "command_in_flight", cause: errors.New(sensitive),
	}.Error()

	for name, detail := range map[string]string{
		"system": system, "terminal": terminal,
		"unknown api": unknownAPI, "deferred": deferred,
	} {
		t.Run(name, func(t *testing.T) {
			if detail == "" || len(detail) > 128 || strings.Contains(detail, sensitive) ||
				strings.Contains(detail, "alice") || strings.Contains(detail, "super-secret") {
				t.Fatalf("durable scheduler detail is not closed and bounded: %q", detail)
			}
		})
	}
	if terminal != "connector delivery failed" {
		t.Fatalf("connector failure classification = %q", terminal)
	}
	if got := secretRotationScheduleTerminalErrorDetail(
		errStatus(503, connectorRotationTargetUnavailableDetail),
	); got != connectorRotationTargetUnavailableDetail {
		t.Fatalf("known fixed API detail = %q", got)
	}
}

func TestSecretRotationScheduleResponsesCollapseHistoricalRawErrors(t *testing.T) {
	const sensitive = "credential=super-secret subject=alice@example.test remote=vault/alice"
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	schedule := store.SecretRotationSchedule{
		ID: "16100000-0000-4000-8000-000000000021", TenantID: "tenant-a",
		LastRunStatus: "delivery_failed", LastError: sensitive, NextRunAt: dueAt,
	}
	listed := toSecretRotationScheduleResponse(schedule)
	if listed.LastError != "connector delivery failed" || strings.Contains(listed.LastError, sensitive) {
		t.Fatalf("historical schedule GET detail = %q", listed.LastError)
	}
	replayed := secretRotationScheduleRunResponseFromReceipt(schedule, store.SecretRotationScheduleRun{
		ScheduleID: schedule.ID, RunID: "16100000-0000-4000-8000-000000000022",
		DueAt: dueAt, Status: "delivery_failed", Error: sensitive, RanAt: dueAt,
	}, true)
	if replayed.Error != "connector delivery failed" ||
		replayed.Rotation.Error != "connector delivery failed" ||
		strings.Contains(replayed.Error, sensitive) {
		t.Fatalf("historical retained-event response = %+v", replayed)
	}
}

func TestSecretRotationScheduleSystemFailureClearsSuccessfulLimitEvidence(t *testing.T) {
	resp := secretRotationDueRunResponse{
		Runs:             []secretRotationScheduleRunResponse{{ScheduleID: "schedule-a"}},
		RunLimitReached:  true,
		ScanLimitReached: true,
		Complete:         true,
	}
	markSecretRotationScheduleDueRunFailed(
		&resp, "schedule-b", store.SecretRotationScheduleTickProcessingError)
	if resp.Complete || resp.RunLimitReached || resp.ScanLimitReached || !resp.Partial ||
		resp.FailedScheduleID != "schedule-b" ||
		resp.SystemError != store.SecretRotationScheduleTickProcessingError {
		t.Fatalf("post-boundary scheduler failure retained successful limit evidence: %+v", resp)
	}
}
