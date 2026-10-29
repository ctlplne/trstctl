// SPDX-License-Identifier: BUSL-1.1

package events

import "context"

type suppressedActor struct{}

// ContextWithoutActor keeps deadlines, cancellation and operation grants while
// preventing a background machine control from copying a person's actor into
// its public recovery record. The parent/request event retains attribution.
func ContextWithoutActor(ctx context.Context) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, suppressedActor{})
}
