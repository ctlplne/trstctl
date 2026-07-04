// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/events"
)

// TestProtocolAuditDoesNotSilentlyDropAppendFailures is the CORRECT-004 acceptance
// for the served protocol issuance/revocation/profile audit emits. Before the fix
// the three helpers used `_, _ = p.log.Append(...)` and silently swallowed an
// event-log append failure, so a lost AN-2 protocol audit record left no trace. The
// fix routes them through auditsink.Emit, which increments the process-wide
// dropped-event counter (and WARN-logs) on failure.
//
// A zero-value *events.Log with an empty tenant id makes Append fail deterministically
// (it validates tenant_id before publishing), so the test needs no live NATS. Before
// the fix the counter is unchanged (test fails); after the fix it advances by one per
// emit.
func TestProtocolAuditDoesNotSilentlyDropAppendFailures(t *testing.T) {
	p := &protocolIssuer{log: &events.Log{}} // non-nil log; Append fails on empty tenant
	ctx := context.Background()

	before := auditsink.DroppedEvents()

	// Empty tenant id forces a clean Append error on each emit.
	p.auditIssued(ctx, "", "acme", "01")
	p.auditRevoked(ctx, "", "acme", "01", 0)
	p.auditProfileDecision(ctx, "", "acme", 1, "allow", "")

	if got, want := auditsink.DroppedEvents(), before+3; got != want {
		t.Fatalf("DroppedEvents = %d; want %d: a failed protocol audit append must be counted, not swallowed (CORRECT-004)", got, want)
	}
}
