// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestReplayTenantThroughConcurrentReplicaCatchup(t *testing.T) {
	ctx := t.Context()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded,
		StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	replica := openSecondReplicaLog(t, log, log.history)
	t.Cleanup(func() { _ = replica.Close() })
	for i := 0; i < 40; i++ {
		tenant := "tenant-a"
		if i%3 == 0 {
			tenant = "tenant-b"
		}
		if _, err := log.Append(ctx, Event{TenantID: tenant, Type: "test.event", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, reader := range []*Log{log, replica} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			count := 0
			err := reader.ReplayTenantThrough(ctx, "tenant-a", 1, head, func(Event) error {
				count++
				return nil
			})
			if err == nil && count != 26 {
				err = errors.New("concurrent tenant projection returned an incomplete page")
			}
			results <- err
		}()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplayTenantThroughCheckpointPruneColdCursor(t *testing.T) {
	ctx := t.Context()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := openRewriteLog(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, Event{ID: "pruned-source", TenantID: tenantID,
		Type: "secret.version.written", Data: []byte(`{"sealed":"deployment-ciphertext"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.RewriteTenantData(ctx, tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
		}, rewriteProofOptions(t)...); err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.PruneTenantThroughCheckpoint(ctx, tenantID, head,
		func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = openRewriteLog(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	read := func(cut uint64) []uint64 {
		t.Helper()
		got := []uint64{}
		if err := log.ReplayTenantThrough(ctx, tenantID, 1, cut, func(ev Event) error {
			got = append(got, ev.Sequence)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(head); len(got) != 0 {
		t.Fatalf("checkpoint-pruned tenant history returned %v", got)
	}
	next, err := log.Append(ctx, Event{ID: "post-prune", TenantID: tenantID,
		Type: "secret.version.written", Data: []byte(`{"sealed":"new"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(next.Sequence); !slices.Equal(got, []uint64{next.Sequence}) {
		t.Fatalf("post-prune tenant history = %v, want only %d", got, next.Sequence)
	}
}

func TestReplayTenantThroughKeepsSourceOrderCutAndColdRecovery(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var source []Event
	for _, item := range []struct{ tenant, typ string }{
		{"tenant-a", "owner.created"}, {"tenant-b", "secret.issued"},
		{"tenant-a", "certificate.recorded"}, {"tenant-b", "owner.created"},
		{"tenant-a", "secret.revoked"},
	} {
		ev, err := log.Append(ctx, Event{TenantID: item.tenant, Type: item.typ, Data: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		source = append(source, ev)
	}
	read := func(log *Log, from, through uint64) []uint64 {
		t.Helper()
		got := []uint64{}
		if err := log.ReplayTenantThrough(ctx, "tenant-a", from, through, func(ev Event) error {
			if ev.TenantID != "tenant-a" {
				t.Fatalf("cross-tenant event escaped index: %+v", ev)
			}
			got = append(got, ev.Sequence)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := read(log, 1, source[3].Sequence); !slices.Equal(got, []uint64{1, 3}) {
		t.Fatalf("finite tenant cut = %v, want [1 3]", got)
	}
	if got := read(log, 3, source[4].Sequence); !slices.Equal(got, []uint64{3, 5}) {
		t.Fatalf("later tenant range = %v, want [3 5]", got)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if got := read(log, 1, source[4].Sequence); !slices.Equal(got, []uint64{1, 3, 5}) {
		t.Fatalf("cold tenant index = %v, want [1 3 5]", got)
	}
	if err := log.ReplayTenantThrough(ctx, "tenant-a", 1, source[4].Sequence+1, func(Event) error { return nil }); err == nil {
		t.Fatal("source cut beyond the head was accepted")
	}
}

func TestReplayTenantThroughResumesBoundedIndexAfterRequestInterruption(t *testing.T) {
	ctx := t.Context()
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := uint64(0); i <= tenantIndexReadLimit; i++ {
		if _, err := log.Append(ctx, Event{TenantID: "tenant-a", Type: "test.event", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.ReplayTenantThrough(ctx, "tenant-a", 1, head, func(Event) error { return nil }); !errors.Is(err, ErrTenantIndexBehind) {
		t.Fatalf("first bounded catch-up = %v, want retryable behind", err)
	}
	var count uint64
	if err := log.ReplayTenantThrough(ctx, "tenant-a", 1, head, func(Event) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != head {
		t.Fatalf("completed tenant index returned %d events, want %d", count, head)
	}
}
