// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
)

// Decode one already bounded transport page with at most four workers. Only
// decoding runs concurrently: callbacks, errors and privacy decisions remain in
// source order. A page is fully released before another page is fetched, so
// decoded public payloads add at most one page to the existing memory bound.
const retainedDecodeWorkers = 4

func readRetainedEventsThrough(ctx context.Context, stream jetstream.Stream, from, through uint64, visit func(Event) error) error {
	if from == 0 {
		from = 1
	}
	if from > through {
		return ctx.Err()
	}
	if paged, ok := stream.(interface {
		readRetainedPages(context.Context, uint64, uint64, func([]*jetstream.RawStreamMsg) error) error
	}); ok {
		return paged.readRetainedPages(ctx, from, through, func(page []*jetstream.RawStreamMsg) error {
			return visitDecodedRetainedPage(ctx, page, visit)
		})
	}
	return readRetainedThrough(ctx, stream, from, through, func(raw *jetstream.RawStreamMsg) error {
		event, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		return visit(event)
	})
}

func visitDecodedRetainedPage(ctx context.Context, page []*jetstream.RawStreamMsg, visit func(Event) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	type result struct {
		event Event
		err   error
	}
	decoded := make([]result, len(page))
	workers := min(retainedDecodeWorkers, len(page))
	decode := func(start int) {
		for i := start; i < len(page); i += workers {
			if ctx.Err() != nil {
				return
			}
			decoded[i].event, decoded[i].err = decodeStored(page[i].Data, page[i].Sequence)
		}
	}
	if workers == 1 {
		decode(0)
	} else {
		var group sync.WaitGroup
		for start := range workers {
			group.Add(1)
			go func() { defer group.Done(); decode(start) }()
		}
		group.Wait()
	}
	for _, item := range decoded {
		if err := ctx.Err(); err != nil {
			return err
		}
		if item.err != nil {
			return item.err
		}
		if err := visit(item.event); err != nil {
			return err
		}
	}
	return ctx.Err()
}
