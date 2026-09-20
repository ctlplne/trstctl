// SPDX-License-Identifier: BUSL-1.1

package scep

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/events"
)

// TestSCEPAuditDoesNotSilentlyDropAppendFailures is the CORRECT-004 acceptance for
// the SCEP enrollment audit emit. Before the fix audit() swallowed a failed
// event-log append with `_, _ =`; after the fix it routes through auditsink.Emit,
// so a dropped AN-2 enrollment record increments the process-wide counter.
func TestSCEPAuditDoesNotSilentlyDropAppendFailures(t *testing.T) {
	s := &Server{log: &events.Log{}}
	before := auditsink.DroppedEvents()

	s.audit(context.Background(), "allow", "", "txn-1")

	if got, want := auditsink.DroppedEvents(), before+1; got != want {
		t.Fatalf("DroppedEvents = %d; want %d: a failed SCEP audit append must be counted, not swallowed (CORRECT-004)", got, want)
	}
}
