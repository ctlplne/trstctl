// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
)

// At most eight stored-message requests and result buffers belong to one replay.
// Only transport scheduling changes; callbacks and errors retain sequence order.
const retainedReadWindow = 8

func readRetainedThrough(ctx context.Context, stream jetstream.Stream, from, through uint64, visit func(*jetstream.RawStreamMsg) error) error {
	if from == 0 {
		from = 1
	}
	if from > through {
		return ctx.Err()
	}
	if batched, ok := stream.(interface {
		readRetainedRange(context.Context, uint64, uint64, func(*jetstream.RawStreamMsg) error) error
	}); ok {
		return batched.readRetainedRange(ctx, from, through, visit)
	}
	readCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	type result struct {
		raw *jetstream.RawStreamMsg
		err error
	}
	count := min(uint64(retainedReadWindow), through-from+1)
	rows := make([]chan result, count)
	for i := range rows {
		// Each reader owns at most one response. Unbuffered handoff keeps a
		// slow callback from accumulating an unbounded read-ahead queue.
		rows[i] = make(chan result)
		workers.Add(1)
		go func(sequence uint64, out chan<- result) {
			defer workers.Done()
			for {
				if readCtx.Err() != nil {
					return
				}
				raw, err := stream.GetMsg(readCtx, sequence)
				select {
				case out <- result{raw, err}:
				case <-readCtx.Done():
					return
				}
				if through-sequence < count {
					return
				} // Never wrap a MaxUint64 cut into zero.
				sequence += count
			}
		}(from+uint64(i), rows[i])
	}
	for sequence := from; ; sequence++ {
		var item result
		select {
		case <-readCtx.Done():
			return readCtx.Err()
		case item = <-rows[(sequence-from)%count]:
		}
		if err := readCtx.Err(); err != nil {
			return err
		}
		if !errors.Is(item.err, jetstream.ErrMsgNotFound) {
			if item.err != nil {
				return fmt.Errorf("events: get seq %d: %w", sequence, item.err)
			}
			if item.raw == nil || item.raw.Sequence != sequence {
				return fmt.Errorf("events: retained read returned the wrong sequence for %d", sequence)
			}
			if err := visit(item.raw); err != nil {
				return err
			}
		}
		if sequence == through {
			break
		}
	}
	return nil
}
