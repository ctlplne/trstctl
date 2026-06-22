package trstctl

import "context"

// Iterator lazily pages through a cursor-paginated list, following the server's
// next_cursor field so callers never juggle cursors by hand. Typical use:
//
//	it := client.Owners(trstctl.ListOptions{Limit: 50})
//	for it.Next(ctx) {
//	    owner := it.Value()
//	    // ... use owner ...
//	}
//	if err := it.Err(); err != nil {
//	    // handle the failure (it stops at the first error)
//	}
//
// An Iterator is single-pass and not safe for concurrent use. It fetches the
// next page only when the current page is exhausted and there is a next_cursor,
// so it makes the minimum number of round-trips.
type Iterator[T any] struct {
	opts  ListOptions
	fetch func(ctx context.Context, opts ListOptions) (*Page[T], error)

	page    []T
	idx     int
	cursor  string
	started bool
	done    bool
	err     error
}

func newIterator[T any](opts ListOptions, fetch func(ctx context.Context, opts ListOptions) (*Page[T], error)) *Iterator[T] {
	return &Iterator[T]{opts: opts, fetch: fetch, cursor: opts.Cursor}
}

// Next advances to the next item, fetching the next page if needed. It returns
// false when the list is exhausted or an error occurred; check Err after the
// loop. A cancelled ctx surfaces as an error and stops iteration.
func (it *Iterator[T]) Next(ctx context.Context) bool {
	if it.err != nil {
		return false
	}
	// Serve from the buffered page first.
	if it.idx < len(it.page) {
		it.idx++
		return true
	}
	// Page exhausted. Stop unless this is the first fetch or there's a cursor.
	if it.started && it.cursor == "" {
		it.done = true
		return false
	}
	if it.done {
		return false
	}
	if err := ctx.Err(); err != nil {
		it.err = err
		return false
	}

	opts := it.opts
	opts.Cursor = it.cursor
	pg, err := it.fetch(ctx, opts)
	if err != nil {
		it.err = err
		return false
	}
	it.started = true
	it.page = pg.Items
	it.cursor = pg.NextCursor
	it.idx = 0

	if len(it.page) == 0 {
		// Empty page: if there's still a cursor the server wants us to keep
		// going; otherwise we're done.
		if it.cursor == "" {
			it.done = true
			return false
		}
		return it.Next(ctx)
	}
	it.idx++
	return true
}

// Value returns the current item. It is only valid after Next returned true.
func (it *Iterator[T]) Value() T {
	if it.idx == 0 || it.idx > len(it.page) {
		var zero T
		return zero
	}
	return it.page[it.idx-1]
}

// Err returns the first error that stopped iteration, or nil. A *Problem is
// returned for an API error (use AsProblem to inspect it).
func (it *Iterator[T]) Err() error { return it.err }

// Collect drains the iterator into a slice. It is a convenience for callers that
// want every item at once (and accept holding them all in memory). It returns
// the items collected so far alongside any error.
func (it *Iterator[T]) Collect(ctx context.Context) ([]T, error) {
	var all []T
	for it.Next(ctx) {
		all = append(all, it.Value())
	}
	return all, it.Err()
}
