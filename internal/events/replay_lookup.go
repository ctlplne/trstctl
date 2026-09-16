// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/schedulerhistory"
)

// ReplayThroughAndLookup recovers a finite prefix and finds one producer ID in
// that same prefix. It reads every envelope through the cut, including those
// before from, so an old canonical event or conflicting duplicate cannot hide
// behind a caller's projection cursor. Only events at or after from reach fn.
//
// The normal replay privacy preflight and generation fence remain in force.
// Callbacks can run before a later error; callers must roll back their projected
// effects on any error, just as with ReplayThrough. No lookup result is returned
// until the entire cut succeeds. Nothing is cached between commands.
func (l *Log) ReplayThroughAndLookup(ctx context.Context, from, through uint64, eventID string, fn func(Event) error) (Event, bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return Event{}, false, errors.New("events: event id lookup is empty")
	}
	var canonical Event
	found := false
	err := l.ReplayThrough(ctx, 1, through, func(event Event) error {
		if event.ID == eventID {
			// Even when the global legacy floor is not installed, an unsafe
			// matching envelope must never escape through the lookup result.
			unsafe, inspectErr := schedulerhistory.RequiresSanitation(event.Type, event.SchemaVersion, event.Data)
			if inspectErr != nil || unsafe {
				return schedulerhistory.ErrSanitationRequired
			}
			if !found {
				canonical = event
				canonical.Data = bytes.Clone(event.Data)
				if event.Actor != nil {
					actor := *event.Actor
					actor.Roles = slices.Clone(event.Actor.Roles)
					canonical.Actor = &actor
				}
				found = true
			} else if !sameRetainedEvent(canonical, event) {
				return fmt.Errorf("%w: event id %q has conflicting retained envelopes at sequences %d and %d", ErrConflictingEventIdentity, eventID, canonical.Sequence, event.Sequence)
			}
		}
		if event.Sequence >= from {
			return fn(event)
		}
		return nil
	})
	if err != nil {
		return Event{}, false, err
	}
	return canonical, found, nil
}

func sameRetainedEvent(left, right Event) bool {
	return left.Type == right.Type && left.TenantID == right.TenantID &&
		left.Time.Equal(right.Time) && left.SchemaVersion == right.SchemaVersion &&
		bytes.Equal(left.Data, right.Data) && reflect.DeepEqual(left.Actor, right.Actor)
}
