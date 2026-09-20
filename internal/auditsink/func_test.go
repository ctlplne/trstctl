// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"context"
	"errors"
	"testing"
)

// TestAuditorFuncRoutesThroughEmitAccounting is the CORRECT-004 acceptance for the
// AuditorFunc adapter: a caller holding a concrete event-log handle can wrap its
// append in AuditorFunc and get Emit's dropped-event accounting. A failing append
// surfaces the error and increments the counter; a succeeding one does neither.
func TestAuditorFuncRoutesThroughEmitAccounting(t *testing.T) {
	wantErr := errors.New("append failed")
	failing := AuditorFunc(func(context.Context, string, string, []byte) error { return wantErr })

	before := DroppedEvents()
	if err := Emit(context.Background(), failing, nil, "protocol.issued", "t1", []byte(`{}`)); !errors.Is(err, wantErr) {
		t.Fatalf("Emit over failing AuditorFunc = %v; want %v", err, wantErr)
	}
	if got := DroppedEvents(); got != before+1 {
		t.Fatalf("DroppedEvents = %d; want %d", got, before+1)
	}

	var called bool
	ok := AuditorFunc(func(context.Context, string, string, []byte) error { called = true; return nil })
	before = DroppedEvents()
	if err := Emit(context.Background(), ok, nil, "protocol.issued", "t1", []byte(`{}`)); err != nil {
		t.Fatalf("Emit over ok AuditorFunc = %v; want nil", err)
	}
	if !called {
		t.Fatal("AuditorFunc was not invoked by Emit")
	}
	if got := DroppedEvents(); got != before {
		t.Fatalf("DroppedEvents changed %d->%d on success; want unchanged", before, got)
	}
}

// TestNilAuditorFuncIsSafe verifies a nil AuditorFunc behaves as a no-op auditor.
func TestNilAuditorFuncIsSafe(t *testing.T) {
	var f AuditorFunc
	if err := f.Audit(context.Background(), "x", "t1", nil); err != nil {
		t.Fatalf("nil AuditorFunc.Audit = %v; want nil", err)
	}
}
