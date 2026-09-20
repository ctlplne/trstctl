// SPDX-License-Identifier: BUSL-1.1

// Package rotationcommand defines the deterministic identity of one scheduled
// secret-rotation due edge. It is a small leaf so the command side, projector,
// and PostgreSQL receiver validate the same tuple without importing each other.
package rotationcommand

import (
	"encoding/binary"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var namespace = uuid.MustParse("fd264f5e-e55a-53bd-9321-3225305af02a")

const (
	// OuterKeyV3Prefix marks aggregate scheduler idempotency keys whose opaque
	// suffix binds the raw caller key to one tenant registration. Keeping the
	// prefix beside the command identity domains lets the API producer and the
	// PostgreSQL startup validator classify the same lifecycle-aware authority.
	OuterKeyV3Prefix = "secret-rotation-schedule-tick:v3:"
	// LegacyBoundEventSchemaVersion carried the exact due edge but did not bind
	// it to a tenant registration. It remains replay-readable only as old history.
	LegacyBoundEventSchemaVersion = 2
	// EventSchemaVersion binds every identity to the canonical tenant.registered
	// event so a reused tenant UUID starts a disjoint command namespace.
	EventSchemaVersion = 3
)

// RunID binds one command to one exact tenant registration, schedule, and due
// time. Length framing makes the tuple unambiguous even if a future identity
// format admits characters that were separators in an older schema.
func RunID(tenantID string, tenantRegistrationEventSequence uint64, scheduleID string, dueAt time.Time) string {
	return uuid.NewSHA1(namespace, framed(
		"trstctl.secret-rotation-schedule.run.v3",
		tenantID, strconv.FormatUint(tenantRegistrationEventSequence, 10), scheduleID,
		dueAt.UTC().Format(time.RFC3339Nano),
	)).String()
}

// LegacyRunID reconstructs immutable version-2 history. New producers must use
// RunID so a re-registration cannot reuse this tenant-UUID-only namespace.
func LegacyRunID(tenantID, scheduleID string, dueAt time.Time) string {
	return uuid.NewSHA1(namespace, []byte(
		"run\x00"+tenantID+"\x00"+scheduleID+"\x00"+dueAt.UTC().Format(time.RFC3339Nano))).String()
}

// CommandKey is the inner idempotency identity shared with the connector
// application-secret mutation.
func CommandKey(runID string) string {
	return "secret-rotation-schedule-command:" + runID
}

// TerminalEventID is the immutable receipt identity for a run.
func TerminalEventID(runID string) string {
	return uuid.NewSHA1(namespace, []byte("terminal\x00"+runID)).String()
}

// Matches proves that all derivable identities belong to the supplied due edge.
func Matches(tenantID string, tenantRegistrationEventSequence uint64, scheduleID, runID string, dueAt time.Time, commandKey, terminalEventID string) bool {
	return tenantRegistrationEventSequence > 0 && !dueAt.IsZero() &&
		runID == RunID(tenantID, tenantRegistrationEventSequence, scheduleID, dueAt) &&
		commandKey == CommandKey(runID) && terminalEventID == TerminalEventID(runID)
}

// LegacyMatches validates only already-retained version-2 history.
func LegacyMatches(tenantID, scheduleID, runID string, dueAt time.Time, commandKey, terminalEventID string) bool {
	return !dueAt.IsZero() && runID == LegacyRunID(tenantID, scheduleID, dueAt) &&
		commandKey == CommandKey(runID) && terminalEventID == TerminalEventID(runID)
}

func framed(domain string, fields ...string) []byte {
	size := 8 + len(domain)
	for _, field := range fields {
		size += 8 + len(field)
	}
	out := make([]byte, 0, size)
	out = appendLengthPrefixed(out, domain)
	for _, field := range fields {
		out = appendLengthPrefixed(out, field)
	}
	return out
}

func appendLengthPrefixed(dst []byte, value string) []byte {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}
