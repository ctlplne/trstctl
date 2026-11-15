// SPDX-License-Identifier: BUSL-1.1

package store

import "context"

type effectsAlreadyQueuedKey struct{}

// WithEffectsAlreadyQueued marks ctx as re-projecting an event this
// deployment projected before (A237L4-L1). A full rebuild re-derives the read
// model from the log, but the event's external effects (a decoy's alert, a
// report's removal) were queued when the event was first projected, and the
// outbox row that kept a replay from queuing one twice is reclaimed a day
// after delivery (outboxgc's default retention). An apply that sees this mark
// changes the read model as always and queues no effect.
func WithEffectsAlreadyQueued(ctx context.Context) context.Context {
	return context.WithValue(ctx, effectsAlreadyQueuedKey{}, true)
}

// effectsAlreadyQueued reports whether ctx re-projects an event whose effects
// were queued when it was first projected (WithEffectsAlreadyQueued).
func effectsAlreadyQueued(ctx context.Context) bool {
	queued, _ := ctx.Value(effectsAlreadyQueuedKey{}).(bool)
	return queued
}
