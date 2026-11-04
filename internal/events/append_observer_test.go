// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// CI-L37: the append observer hears each Append's wall time; without one,
// Append is unchanged.
func TestAppendObserverTimesEachAppend(t *testing.T) {
	var mu sync.Mutex
	var heard []time.Duration
	log, err := Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		WithAppendObserver(func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			heard = append(heard, d)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 0; i < 2; i++ {
		if _, err := log.Append(context.Background(), Event{Type: "test.observed", TenantID: "11111111-1111-1111-1111-111111111111", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(heard) != 2 || heard[0] <= 0 || heard[1] <= 0 {
		t.Fatalf("heard %v", heard)
	}
}
