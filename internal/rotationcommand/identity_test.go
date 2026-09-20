// SPDX-License-Identifier: BUSL-1.1

package rotationcommand

import (
	"testing"
	"time"
)

func TestRunIDSeparatesTenantRegistrationLifecycles(t *testing.T) {
	const (
		tenantID   = "11111111-1111-1111-1111-111111111111"
		scheduleID = "10600000-0000-4000-8000-000000000001"
	)
	dueAt := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	first := RunID(tenantID, 41, scheduleID, dueAt)
	retry := RunID(tenantID, 41, scheduleID, dueAt)
	next := RunID(tenantID, 42, scheduleID, dueAt)
	legacy := LegacyRunID(tenantID, scheduleID, dueAt)
	if first != retry {
		t.Fatalf("same lifecycle due edge is not deterministic: %q != %q", first, retry)
	}
	if first == next || first == legacy || next == legacy {
		t.Fatalf("lifecycle namespaces overlap: v3/41=%q v3/42=%q v2=%q", first, next, legacy)
	}
	if !Matches(tenantID, 41, scheduleID, first, dueAt, CommandKey(first), TerminalEventID(first)) {
		t.Fatal("v3 identity tuple did not self-validate")
	}
	if Matches(tenantID, 42, scheduleID, first, dueAt, CommandKey(first), TerminalEventID(first)) {
		t.Fatal("run from prior registration validated in current lifecycle")
	}
	if !LegacyMatches(tenantID, scheduleID, legacy, dueAt, CommandKey(legacy), TerminalEventID(legacy)) {
		t.Fatal("N-1 identity is no longer replay-readable")
	}
}
