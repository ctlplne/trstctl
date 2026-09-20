// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"

	"trstctl.com/trstctl/internal/eventspec"
)

// Actor is defined in internal/eventspec (a NATS-free leaf) and re-exported here as
// an alias so every events.Actor reference keeps working and stays the identical
// type. The context helpers below operate on it.
type Actor = eventspec.Actor

type actorCtxKey struct{}

// ContextWithActor returns a context that attributes events appended under it to
// a. The API sets this from the resolved principal so the orchestrator's commands
// — which all funnel through Append — record the actor without threading it
// through every signature.
func ContextWithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

// ActorFromContext returns the actor carried by ctx, if one was set.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorCtxKey{}).(Actor)
	return a, ok
}
