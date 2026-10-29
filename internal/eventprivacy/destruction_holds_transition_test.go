// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestRetainedHoldDecoderCannotSmuggleDuplicateOrUnknownReleaseAuthority(t *testing.T) {
	for _, wire := range []string{
		`{"id":"fixture-hold","status":"failed","status":"released"}`,
		`{"id":"fixture-hold","status":"released","release_requested":true}`,
		`{"id":"fixture-hold","status":"released"} {}`,
		`null`,
	} {
		state := retainedHoldState{archive: map[string]retainedArchiveHold{"fixture-hold": {object: "fixture-object", phase: "release_pending"}}, objectOwner: map[string]string{"fixture-object": "fixture-hold"}, reports: map[string]bool{}}
		if err := state.apply(events.Event{Type: archiveHoldRecorded, Data: []byte(wire)}); err == nil {
			t.Fatalf("ambiguous hold authority accepted: %s", wire)
		}
		if state.archive["fixture-hold"].phase == "released" {
			t.Fatal("invalid source mutated hold authority")
		}
	}
}

func TestRetainedFailedHoldCannotClearASeparateActiveHoldOnSameObject(t *testing.T) {
	state := retainedHoldState{archive: map[string]retainedArchiveHold{"failed": {object: "object", phase: "failed"}, "active": {object: "object", phase: "applied"}}, objectOwner: map[string]string{"object": "active"}, reports: map[string]bool{}}
	if err := state.release("failed"); err != nil {
		t.Fatal(err)
	}
	if state.archive["failed"].phase != "failed" || state.objectOwner["object"] != "active" {
		t.Fatal("failed hold stole another hold's release authority")
	}
}
