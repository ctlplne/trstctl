// SPDX-License-Identifier: MPL-2.0

package auditsink

import (
	"context"
	"errors"
	"testing"
)

type erroringAuditor struct{ err error }

func (e erroringAuditor) Audit(context.Context, string, string, []byte) error { return e.err }

// TestEmitCountsDroppedEventsAndReturnsError is the CODE-001 acceptance for the
// non-discarding emit idiom: when the underlying Audit fails, Emit returns the
// error AND increments the process-wide dropped-event counter, so a lost AN-2
// source-of-truth/audit record is observable instead of silently swallowed (the
// failure mode of a bare `_ = a.Audit(...)`).
func TestEmitCountsDroppedEventsAndReturnsError(t *testing.T) {
	before := DroppedEvents()

	wantErr := errors.New("event log unavailable")
	err := Emit(context.Background(), erroringAuditor{err: wantErr}, nil, "secret.version.written", "t1", []byte(`{}`))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Emit returned %v; want it to surface the underlying error %v", err, wantErr)
	}
	if got := DroppedEvents(); got != before+1 {
		t.Fatalf("DroppedEvents = %d; want %d (a dropped emit must increment the counter)", got, before+1)
	}
}

// TestEmitSuccessDoesNotCountAsDropped verifies a successful emit neither errors
// nor inflates the dropped-event counter (no false integrity alarms).
func TestEmitSuccessDoesNotCountAsDropped(t *testing.T) {
	before := DroppedEvents()
	if err := Emit(context.Background(), Nop{}, nil, "x.ok", "t1", []byte(`{}`)); err != nil {
		t.Fatalf("Emit over a Nop auditor returned %v; want nil", err)
	}
	if got := DroppedEvents(); got != before {
		t.Fatalf("DroppedEvents moved from %d to %d on a successful emit; want unchanged", before, got)
	}
}

// TestEmitNilAuditorIsSafe verifies Emit treats a nil auditor as a no-op (the
// "no auditor wired" default) without panicking or counting a drop.
func TestEmitNilAuditorIsSafe(t *testing.T) {
	before := DroppedEvents()
	if err := Emit(context.Background(), nil, nil, "x", "t1", nil); err != nil {
		t.Fatalf("Emit(nil auditor) = %v; want nil", err)
	}
	if got := DroppedEvents(); got != before {
		t.Fatalf("Emit(nil auditor) changed DroppedEvents %d->%d; want unchanged", before, got)
	}
}
