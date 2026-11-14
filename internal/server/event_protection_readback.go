// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"trstctl.com/trstctl/internal/eventprotect"
)

// statusReadbackSlots bounds how many tenant keys the event-protection status
// route opens at once, across every tenant (A233-L4), as the readiness probe's
// one slot bounds its custody check.
const statusReadbackSlots = 4

// errReadbackBusy is a status read that found every readback slot taken for
// its whole budget; the route answers unavailable, never a guess.
var errReadbackBusy = errors.New("event protection: every key readback slot is busy")

// keyReadbacks shares and bounds the status route's key readbacks: reads of
// the same key while one is open wait for its answer instead of opening the
// key again, and at most statusReadbackSlots keys are open at once. Nothing is
// cached past the open readback, so a changed custody file reads degraded on
// the next request.
type keyReadbacks struct {
	slots    chan struct{}
	mu       sync.Mutex
	inflight map[eventprotect.KeyRef]*keyReadbackCall
	// opened counts the readbacks actually performed.
	opened atomic.Int64
}

type keyReadbackCall struct {
	done chan struct{}
	err  error
}

func newKeyReadbacks() *keyReadbacks {
	return &keyReadbacks{slots: make(chan struct{}, statusReadbackSlots), inflight: map[eventprotect.KeyRef]*keyReadbackCall{}}
}

// readBack runs read for ref, or waits for the readback of ref already open.
// A new readback waits for a slot no longer than ctx allows.
func (k *keyReadbacks) readBack(ctx context.Context, ref eventprotect.KeyRef, read func(context.Context) error) error {
	k.mu.Lock()
	if call, ok := k.inflight[ref]; ok {
		k.mu.Unlock()
		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	call := &keyReadbackCall{done: make(chan struct{})}
	k.inflight[ref] = call
	k.mu.Unlock()
	finish := func(err error) error {
		call.err = err
		k.mu.Lock()
		delete(k.inflight, ref)
		k.mu.Unlock()
		close(call.done)
		return err
	}
	select {
	case k.slots <- struct{}{}:
	case <-ctx.Done():
		return finish(errReadbackBusy)
	}
	defer func() { <-k.slots }()
	k.opened.Add(1)
	return finish(read(ctx))
}
