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
	readCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	type result struct {
		raw *jetstream.RawStreamMsg
		err error
	}
	for from <= through {
		if err := readCtx.Err(); err != nil {
			return err
		}
		count := min(uint64(retainedReadWindow), through-from+1)
		rows := make([]chan result, count)
		for i := range rows {
			rows[i] = make(chan result, 1)
			workers.Add(1)
			go func(sequence uint64, out chan<- result) {
				defer workers.Done()
				raw, err := stream.GetMsg(readCtx, sequence)
				out <- result{raw, err}
			}(from+uint64(i), rows[i])
		}
		for i, row := range rows {
			var item result
			select {
			case <-readCtx.Done():
				return readCtx.Err()
			case item = <-row:
			}
			if err := readCtx.Err(); err != nil {
				return err
			}
			sequence := from + uint64(i)
			if errors.Is(item.err, jetstream.ErrMsgNotFound) {
				continue
			}
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
		workers.Wait()
		if count == through-from+1 {
			break
		} // Never wrap a MaxUint64 cut into zero.
		from += count
	}
	return nil
}
