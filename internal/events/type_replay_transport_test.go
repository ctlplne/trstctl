// SPDX-License-Identifier: BUSL-1.1

package events

import "testing"

func TestTypedReplayDoesNotFetchUnrelatedEventBodies(t *testing.T) {
	log := openBackupHistoryTestLog(t)
	ctx := t.Context()
	for range 180 {
		if _, err := log.Append(ctx, Event{Type: "test.unrelated", TenantID: "other", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if _, err := log.Append(ctx, Event{Type: "test.selected", TenantID: "target", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := log.nc.Stats()
	seen := 0
	if err := log.ReplayTenantTypesThrough(ctx, "target", 1, head, []string{"test.selected"}, func(Event) error {
		seen++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after := log.nc.Stats()
	if seen != 2 {
		t.Fatalf("typed replay returned %d events, want 2", seen)
	}
	if requests := after.OutMsgs - before.OutMsgs; requests > 24 {
		t.Fatalf("typed replay made %d transport requests for 2 selected among 182 events", requests)
	}
}
