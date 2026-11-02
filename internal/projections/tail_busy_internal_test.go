// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// The tail waits out a busy store (another session holding the tenant's
// event-protection lock, a pool at capacity) instead of recording a tail
// failure and stopping; any other error, or a canceled worker, ends at once.
func TestTailRetriesOnlyWhileTheStoreIsBusy(t *testing.T) {
	ctx := context.Background()
	busy := fmt.Errorf("%w: tenant event protection is in use", store.ErrDatastoreBusy)
	calls := 0
	if err := retryWhileBusy(ctx, func() error {
		calls++
		if calls < 3 {
			return busy
		}
		return nil
	}); err != nil || calls != 3 {
		t.Fatalf("busy twice then applied: err=%v calls=%d", err, calls)
	}
	rejected := errors.New("projection rejected the event")
	calls = 0
	if err := retryWhileBusy(ctx, func() error { calls++; return rejected }); !errors.Is(err, rejected) || calls != 1 {
		t.Fatalf("a rejection was retried: err=%v calls=%d", err, calls)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	if err := retryWhileBusy(canceled, func() error { calls++; return busy }); !errors.Is(err, store.ErrDatastoreBusy) || calls != 1 {
		t.Fatalf("a canceled worker kept waiting: err=%v calls=%d", err, calls)
	}
}
