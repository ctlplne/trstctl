// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
)

// verifyAuthenticatedPosition rejects a valid old envelope republished at a
// later sequence. The durable first-ID index is built in source order before
// trusting a read; a read-only federation source uses the producer's index.
func (l *Log) verifyAuthenticatedPosition(ctx context.Context, event Event) error {
	if l.eventAuth == nil {
		return nil
	}
	if event.ID == "" || event.Sequence == 0 {
		return ErrEventAuthentication
	}
	l.idIndexMu.Lock()
	defer l.idIndexMu.Unlock()
	state, err := l.schedulerSafetySnapshot(ctx)
	if err != nil {
		return err
	}
	name, source, err := l.resolveActiveStream(ctx)
	if err != nil {
		return err
	}
	if name != state.Name || event.Sequence > state.LastSequence {
		return ErrGenerationChanged
	}
	var index jetstream.Stream
	var epoch string
	if l.desiredReplicas == 0 {
		epoch = l.eventIDIndexEpoch(state)
		index, err = l.js.Stream(ctx, eventIDIndexPrefix+epoch)
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			return ErrEventIDIndexBehind
		}
	} else {
		index, epoch, err = l.eventIDIndexFor(ctx, state)
	}
	if err != nil {
		return err
	}
	covered, _, err := readEventIDCursor(ctx, index, epoch, l.eventAuth)
	if err != nil {
		return err
	}
	if covered < event.Sequence && l.desiredReplicas != 0 {
		covered, err = l.indexEventIDsThrough(ctx, source, state, event.Sequence)
		if err != nil {
			return err
		}
	}
	if covered < event.Sequence {
		return fmt.Errorf("%w: first-ID index covers %d of %d", ErrEventIDIndexBehind, covered, event.Sequence)
	}
	entry, _, found, err := readEventIDEntry(ctx, index, epoch, event.ID, l.eventAuth)
	if err != nil {
		return err
	}
	if !found || entry.Sequence != event.Sequence || entry.Conflict {
		return ErrEventAuthentication
	}
	return nil
}
