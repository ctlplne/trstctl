// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventspec"
)

// OD-11: the hold clearance records the operator's audit retention floor
// when it kept the key past the tenant's window: the floor's end, which is
// the offboard plus the floor's whole seconds, after the tenant's own
// not-before, and a retained clearance appended no sooner than that end.
func TestHoldClearanceRecordsTheRetentionFloorOD11(t *testing.T) {
	base := holdClearanceFixture(t)
	var body HoldClearance
	if err := json.Unmarshal(base.Data, &body); err != nil {
		t.Fatal(err)
	}
	floorClearance := func(change func(*HoldClearance, *eventspec.Event)) eventspec.Event {
		b := body
		until := b.Request.OffboardedAt.Add(2 * time.Hour)
		b.RetentionFloorUntil, b.RetentionFloorSeconds = &until, 7200
		event := base
		event.Time = until.Add(time.Second)
		if change != nil {
			change(&b, &event)
		}
		wire, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		event.Data = wire
		return event
	}
	parsed, err := ParseHoldClearance(floorClearance(nil))
	if err != nil || parsed.RetentionFloorSeconds != 7200 || parsed.RetentionFloorUntil == nil ||
		!parsed.RetentionFloorUntil.Equal(body.Request.OffboardedAt.Add(2*time.Hour)) {
		t.Fatalf("a clearance the floor kept = %+v, %v", parsed, err)
	}
	if parsed, err := ParseHoldClearance(base); err != nil || parsed.RetentionFloorUntil != nil || parsed.RetentionFloorSeconds != 0 {
		t.Fatalf("a clearance without a floor = %+v, %v", parsed, err)
	}
	for name, change := range map[string]func(*HoldClearance, *eventspec.Event){
		"an end that is not offboard plus the floor": func(b *HoldClearance, _ *eventspec.Event) {
			until := b.RetentionFloorUntil.Add(time.Minute)
			b.RetentionFloorUntil = &until
		},
		"an end without its seconds": func(b *HoldClearance, _ *eventspec.Event) { b.RetentionFloorSeconds = 0 },
		"seconds without an end":     func(b *HoldClearance, _ *eventspec.Event) { b.RetentionFloorUntil = nil },
		"negative seconds": func(b *HoldClearance, _ *eventspec.Event) {
			until := b.Request.OffboardedAt.Add(-time.Hour)
			b.RetentionFloorUntil, b.RetentionFloorSeconds = &until, -3600
		},
		"a floor inside the tenant's own window": func(b *HoldClearance, _ *eventspec.Event) {
			until := b.Request.OffboardedAt.Add(30 * time.Minute)
			b.RetentionFloorUntil, b.RetentionFloorSeconds = &until, 1800
		},
		"cleared before the floor ended": func(b *HoldClearance, e *eventspec.Event) { e.Time = b.RetentionFloorUntil.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHoldClearance(floorClearance(change)); !errors.Is(err, ErrSource) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// OD-11: the receiver's floor counts whole seconds from the offboard, and
// applies only when it ends after the tenant's own window.
func TestDestructionReceiverRetentionFloorOD11(t *testing.T) {
	event := holdClearanceFixture(t)
	var body HoldClearance
	if err := json.Unmarshal(event.Data, &body); err != nil {
		t.Fatal(err)
	}
	request := body.Request // the tenant's window ends an hour after the offboard
	for name, tc := range map[string]struct {
		floor   time.Duration
		applies bool
		seconds int64
	}{
		"off":                             {0, false, 0},
		"under a second":                  {500 * time.Millisecond, false, 0},
		"inside the tenant's window":      {30 * time.Minute, false, 1800},
		"ending with the tenant's window": {time.Hour, false, 3600},
		"past the tenant's window":        {2*time.Hour + 300*time.Millisecond, true, 7200},
	} {
		until, seconds, applies := DestructionReceiver{RetentionFloor: tc.floor}.retentionFloor(request)
		if applies != tc.applies || (tc.seconds != 0 && seconds != tc.seconds) {
			t.Errorf("%s: until %s seconds %d applies %v", name, until, seconds, applies)
		}
		if applies && !until.Equal(request.OffboardedAt.Add(time.Duration(tc.seconds)*time.Second)) {
			t.Errorf("%s: until %s", name, until)
		}
	}
	err := error(&RetentionFloorError{Until: request.OffboardedAt.Add(2 * time.Hour)})
	if !errors.Is(err, ErrRetentionFloor) {
		t.Fatal("a floor postponement is not ErrRetentionFloor")
	}
}
