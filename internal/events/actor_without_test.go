// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
)

func TestContextWithoutActorPreservesOperationGrantsAndCancellation(t *testing.T) {
	type fixtureGrant struct{}
	parent, cancel := context.WithTimeout(context.WithValue(t.Context(), fixtureGrant{}, "owned grant"), time.Minute)
	defer cancel()
	parent = events.ContextWithActor(parent, events.Actor{Subject: "person@example.invalid"})
	public := events.ContextWithoutActor(parent)
	if _, found := events.ActorFromContext(public); found {
		t.Fatal("public machine control inherited personal attribution")
	}
	if actor, found := events.ActorFromContext(parent); !found || actor.Subject != "person@example.invalid" {
		t.Fatal("clearing child changed request attribution")
	}
	if public.Value(fixtureGrant{}) != "owned grant" {
		t.Fatal("clearing actor dropped the operation grant")
	}
	want, _ := parent.Deadline()
	if got, ok := public.Deadline(); !ok || !got.Equal(want) {
		t.Fatal("clearing actor dropped the deadline")
	}
	cancel()
	if !errors.Is(public.Err(), context.Canceled) {
		t.Fatal("clearing actor detached cancellation")
	}
}
