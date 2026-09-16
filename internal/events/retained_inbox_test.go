// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestRetainedBatchDoesNotAllocateAWholeStreamQueue(t *testing.T) {
	_, stream := fakeRetainedBatch(t, func() []*nats.Msg {
		return []*nats.Msg{batchTestMessage(1, 0, 0), batchTestEnd(1, 0)}
	})
	read := func() {
		page, last, complete, err := stream.readBatch(t.Context(), 1, 1)
		if err != nil || len(page) != 1 || last != 1 || !complete {
			t.Fatalf("one-message batch: count=%d last=%d complete=%v err=%v", len(page), last, complete, err)
		}
	}
	read() // Exclude lazy connection/server setup from the allocation measurement.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const reads = 32
	for range reads {
		read()
	}
	runtime.ReadMemStats(&after)
	perRead := (after.TotalAlloc - before.TotalAlloc) / reads
	t.Logf("one-event retained batch: %d allocated bytes/read", perRead)
	// A request for two response messages must not reserve the client's default
	// 65,536-slot queue (512 KiB on 64-bit hosts). This leaves ample space for
	// actual wire messages and server work, both included in TotalAlloc.
	if perRead > 128<<10 {
		t.Fatalf("small retained read allocates %d bytes; bound the response inbox to its batch", perRead)
	}
}

func TestRetainedBatchConnectionCloseInterruptsReceive(t *testing.T) {
	requested := make(chan struct{})
	log, stream := fakeRetainedBatch(t, func() []*nats.Msg {
		close(requested)
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, _, err := stream.readBatch(ctx, 1, 1)
		done <- err
	}()
	select {
	case <-requested:
	case <-ctx.Done():
		t.Fatal("request was not sent")
	}
	log.nc.Close()
	select {
	case err := <-done:
		if !errors.Is(err, nats.ErrConnectionClosed) {
			t.Fatalf("closed transport returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal("closed transport waited for the request deadline")
	}
}

func TestRetainedInboxRejectsQueueOverflow(t *testing.T) {
	for _, tc := range []struct {
		name            string
		messages, bytes int
	}{
		{"message limit", 2, 4096},
		{"byte limit", 32, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := openBackupHistoryTestLog(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			before := log.nc.NumSubscriptions()
			subject := log.nc.NewInbox()
			inbox, err := subscribeRetainedInbox(ctx, log.nc, subject, tc.messages, tc.bytes)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = inbox.close() }()
			// The callback cannot hand off until next is called. Real queued
			// traffic must trip both pending limits, never silently lose data.
			for range 16 {
				if err := log.nc.Publish(subject, []byte("public response")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case status := <-inbox.status:
				if status != nats.SubscriptionSlowConsumer {
					t.Fatalf("status=%v", status)
				}
			case <-ctx.Done():
				t.Fatal("pending limit did not reject overflowing traffic")
			}
			if _, err := inbox.next(ctx); !errors.Is(err, nats.ErrSlowConsumer) {
				t.Fatalf("overflow exposed a response instead of failing: %v", err)
			}
			if err := inbox.close(); err != nil {
				t.Fatal(err)
			}
			if log.nc.NumSubscriptions() != before {
				t.Fatal("closed inbox left a subscription")
			}
		})
	}
}
