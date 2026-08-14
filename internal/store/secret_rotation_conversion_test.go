// SPDX-License-Identifier: MPL-2.0

package store

import (
	"math"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/rotationcommand"
)

func TestBoundSecretRotationRunRejectsEventSequenceOutsidePostgresBigint(t *testing.T) {
	dueAt := time.Date(2026, time.August, 14, 1, 0, 0, 0, time.UTC)
	const (
		tenantID             = "11111111-1111-4111-8111-111111111111"
		registrationEventID  = "tenant-registration-event"
		registrationSequence = uint64(1)
		scheduleID           = "22222222-2222-4222-8222-222222222222"
	)
	runID := rotationcommand.RunID(tenantID, registrationSequence, scheduleID, dueAt)
	run := SecretRotationScheduleRun{
		TenantID: tenantID, IdentityVersion: SecretRotationScheduleIdentityVersion,
		TenantRegistrationEventID: registrationEventID, TenantRegistrationEventSequence: registrationSequence,
		ScheduleID: scheduleID, RunID: runID, SchemaVersion: rotationcommand.EventSchemaVersion,
		DueAt: dueAt, Provider: "connector:test", Key: "app/test", OldRef: "version:1",
		IntervalSeconds: 60, ConfigEventSequence: 2,
		CommandKey: rotationcommand.CommandKey(runID), RequestBinding: "binding", Status: "completed",
		RanAt: dueAt.Add(time.Second), EventID: rotationcommand.TerminalEventID(runID),
		EventType: "secret.rotation_schedule.ran", EventSequence: math.MaxInt64,
		EventDigest: strings.Repeat("a", 64),
	}
	if err := validateBoundSecretRotationScheduleRun(run); err != nil {
		t.Fatalf("MaxInt64 event sequence rejected: %v", err)
	}
	run.EventSequence = uint64(math.MaxInt64) + 1
	if err := validateBoundSecretRotationScheduleRun(run); err == nil {
		t.Fatal("event sequence above PostgreSQL bigint range was accepted")
	}
}
