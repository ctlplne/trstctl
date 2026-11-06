// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"github.com/jackc/pgx/v5"
	"strings"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestCloudChangeSaturationKeepsNotificationAndDatabaseAvailableA264(t *testing.T) {
	ctx := t.Context()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	configs := bulkhead.DefaultConfigs()
	for i := range configs {
		if configs[i].Name == bulkhead.SubsystemOutboxCloudMachine {
			configs[i].Workers = 2
			configs[i].Queue = 0
		}
	}
	pools := bulkhead.NewSet(configs...)
	started := make(chan struct{}, 2)
	notified := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	srv, err := Build(ctx, Deps{Store: st, Log: log, Bulkhead: pools, OutboxHandler: orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
		if strings.HasPrefix(message.Destination, "cloud.machine.") {
			started <- struct{}{}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		notified <- struct{}{}
		return nil
	})})
	if err != nil {
		unblock()
		pools.Close()
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unblock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "owned-cloud-pool"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, key := range []string{"cloud-one", "cloud-two", "notify"} {
			destination := "cloud.machine.change"
			if key == "notify" {
				destination = "notification.test"
			}
			if _, err := srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: tenantID, Destination: destination, IdempotencyKey: key, EffectLane: "cloud.machine.change:" + key, Payload: []byte(`{}`)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.dispatchOnce(ctx)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("cloud worker did not start")
		}
	}
	select {
	case <-notified:
	case <-time.After(2 * time.Second):
		t.Fatal("cloud IAM calls starved notifications")
	}
	pool := pools.Pool(bulkhead.SubsystemOutboxCloudMachine)
	before := pool.Stats().Rejected
	start := time.Now()
	srv.dispatchOnce(ctx)
	if time.Since(start) > 250*time.Millisecond || pool.Stats().Rejected <= before {
		t.Fatal("full cloud queue failed to reject promptly")
	}
	// A real exclusive SQL lock must still be obtainable while IAM calls wait.
	lockCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, err := acquireOutboxExclusiveProbeLock(lockCtx, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}
