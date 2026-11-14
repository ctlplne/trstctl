// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
)

// A233-L4 Done-when (unit): the status route's key readbacks are shared and
// bounded. Fifty concurrent reads of one tenant key open it once and all get
// its answer; reads of ten different keys open at most statusReadbackSlots at
// once, and one that finds every slot taken for its whole budget is refused
// rather than queued without end; nothing outlives the open readback, so the
// next read opens the key again.
func TestStatusKeyReadbacksAreSharedAndBoundedA233L4(t *testing.T) {
	t.Parallel()
	k := newKeyReadbacks()
	release := make(chan struct{})
	var open, peak atomic.Int64
	read := func(context.Context) error {
		if n := open.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		<-release
		open.Add(-1)
		return nil
	}
	one := eventprotect.KeyRef{TenantID: "tenant-a", ID: "key-a"}
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- k.readBack(context.Background(), one, read)
		}()
	}
	for k.opened.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the other 49 join the open readback
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a shared readback answered %v", err)
		}
	}
	if got := k.opened.Load(); got != 1 {
		t.Fatalf("fifty concurrent reads of one key opened it %d times, want 1", got)
	}

	// Ten different keys: at most statusReadbackSlots open at once; with a
	// short budget the rest are refused, not queued.
	hold := make(chan struct{})
	open.Store(0)
	peak.Store(0)
	blocked := func(context.Context) error {
		if n := open.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		<-hold
		open.Add(-1)
		return nil
	}
	var busy atomic.Int64
	var wg2 sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if err := k.readBack(ctx, eventprotect.KeyRef{TenantID: "tenant", ID: strconv.Itoa(i)}, blocked); errors.Is(err, errReadbackBusy) {
				busy.Add(1)
			}
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	close(hold)
	wg2.Wait()
	if peak.Load() > statusReadbackSlots || busy.Load() != int64(10-statusReadbackSlots) {
		t.Fatalf("ten keys: %d open at once (cap %d), %d refused busy (want %d)", peak.Load(), statusReadbackSlots, busy.Load(), 10-statusReadbackSlots)
	}

	// Nothing is kept: the next read of a key opens it again.
	before := k.opened.Load()
	if err := k.readBack(context.Background(), one, func(context.Context) error { return errors.New("custody changed") }); err == nil {
		t.Fatal("a fresh readback reused an earlier answer")
	}
	if k.opened.Load() != before+1 {
		t.Fatal("the next read did not open the key again")
	}
}
