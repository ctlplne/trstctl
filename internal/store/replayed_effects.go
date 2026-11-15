// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"
)

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

// replayedEffectStatus is the outbox status and delivery time of an effect
// row a projection writes whose id its caller keeps (A237L4-L3): pending, or,
// re-projecting an event projected before (WithEffectsAlreadyQueued),
// delivered now. Such a row is written only when the one first queued is gone
// (the sweep reclaims a delivered row a day after delivery), so the
// dispatcher never runs its effect again, the caller still has an id, and the
// sweep reclaims the row again.
func replayedEffectStatus(ctx context.Context) (string, *time.Time) {
	if !effectsAlreadyQueued(ctx) {
		return "pending", nil
	}
	now := time.Now().UTC()
	return "delivered", &now
}
