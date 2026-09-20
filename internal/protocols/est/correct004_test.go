// SPDX-License-Identifier: BUSL-1.1

package est

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/events"
)

// TestESTAuditDoesNotSilentlyDropAppendFailures is the CORRECT-004 acceptance for
// the EST enrollment audit emit. Before the fix audit() swallowed a failed
// event-log append with `_, _ =`; after the fix it routes through auditsink.Emit,
// so a dropped AN-2 enrollment record increments the process-wide counter.
//
// An empty tenant (no tenant in ctx) makes the zero-value *events.Log Append fail
// before publish, so no live NATS is needed.
func TestESTAuditDoesNotSilentlyDropAppendFailures(t *testing.T) {
	s := &Server{log: &events.Log{}}
	before := auditsink.DroppedEvents()

	s.audit(context.Background(), "simpleenroll", "allow", "")

	if got, want := auditsink.DroppedEvents(), before+1; got != want {
		t.Fatalf("DroppedEvents = %d; want %d: a failed EST audit append must be counted, not swallowed (CORRECT-004)", got, want)
	}
}
