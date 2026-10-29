// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// A single untrusted record cannot clear a previously applied hold that has no
// release request. Unknown fields cannot set that request bit by JSON injection.
func FuzzRetainedHoldRequiresReleaseBeforeClear(f *testing.F) {
	f.Add(uint8(0), []byte(`{"id":"fixture-hold","status":"released"}`))
	f.Add(uint8(0), []byte(`{"id":"fixture-hold","status":"released","release_requested":true}`))
	f.Add(uint8(0), []byte(`{"id":"fixture-hold","status":"failed"}`))
	f.Add(uint8(1), []byte(`{"id":"fixture-hold"}`))
	f.Add(uint8(2), []byte(`{"id":"other-hold","object":"fixture-object"}`))
	f.Add(uint8(3), []byte(`{"run_id":"fixture-run"}`))
	f.Add(uint8(4), []byte(`{"run_id":"fixture-run","storage_hold_id":"fixture-hold","storage_object":"fixture-object"}`))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		state := retainedHoldState{archive: map[string]retainedArchiveHold{"fixture-hold": {object: "fixture-object", phase: "applied"}}, objectOwner: map[string]string{"fixture-object": "fixture-hold"}, reports: map[string]bool{"fixture-run": true}}
		types := []string{archiveHoldRecorded, archiveHoldReleaseRequested, archiveHoldPlaced, reportHoldReleased, reportHoldPlaced}
		_ = state.apply(events.Event{Type: types[int(kind)%len(types)], Data: data})
		if state.archive["fixture-hold"].phase == "released" {
			t.Fatal("unrequested hold release entered authority")
		}
	})
}
