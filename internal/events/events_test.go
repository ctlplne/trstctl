package events_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"certctl.io/certctl/internal/config"
	"certctl.io/certctl/internal/events"
)

func embeddedCfg(t *testing.T) config.NATS {
	t.Helper()
	return config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
}

func openEmbedded(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), embeddedCfg(t))
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	return log
}

func collect(t *testing.T, log *events.Log, from uint64) []events.Event {
	t.Helper()
	var got []events.Event
	if err := log.Replay(context.Background(), from, func(e events.Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

func TestAppendAssignsSequenceAndTime(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()

	e1, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: "t1", Data: []byte("x")})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e1.Sequence != 1 {
		t.Errorf("first append Sequence = %d, want 1", e1.Sequence)
	}
	if e1.Time.IsZero() {
		t.Error("Append should set Time")
	}
	if e1.ID == "" {
		t.Error("Append should assign an ID")
	}

	e2, err := log.Append(ctx, events.Event{Type: "tenant.updated", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e2.Sequence != 2 {
		t.Errorf("second append Sequence = %d, want 2 (monotonic)", e2.Sequence)
	}
}

// TestAppendRequiresTypeAndTenant pins the AN-1 invariant that every event
// carries a tenant_id.
func TestAppendRequiresTypeAndTenant(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()
	if _, err := log.Append(ctx, events.Event{TenantID: "t1"}); err == nil {
		t.Error("Append without a type should fail")
	}
	if _, err := log.Append(ctx, events.Event{Type: "x"}); err == nil {
		t.Error("Append without a tenant_id should fail (AN-1)")
	}
}

func TestReplayOrderedAndDeterministic(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "e", TenantID: "t1", Data: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	first := collect(t, log, 0)
	if len(first) != 5 {
		t.Fatalf("replayed %d events, want 5", len(first))
	}
	for i, e := range first {
		if e.Sequence != uint64(i+1) {
			t.Errorf("event %d has Sequence %d, want %d (ordering)", i, e.Sequence, i+1)
		}
	}
	second := collect(t, log, 0)
	if !reflect.DeepEqual(first, second) {
		t.Error("two replays of the same log differ (not deterministic)")
	}
}

func TestReplayFromSequence(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "e", TenantID: "t1"}); err != nil {
			t.Fatal(err)
		}
	}
	got := collect(t, log, 3)
	if len(got) != 3 || got[0].Sequence != 3 || got[2].Sequence != 5 {
		t.Errorf("replay from 3 = %d events starting at %d; want 3 starting at 3", len(got), seqOrZero(got))
	}
}

func seqOrZero(es []events.Event) uint64 {
	if len(es) == 0 {
		return 0
	}
	return es[0].Sequence
}

// TestDurabilityAcrossReopen proves the file-backed log survives a restart with
// no external services.
func TestDurabilityAcrossReopen(t *testing.T) {
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	ctx := context.Background()

	log1, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := log1.Append(ctx, events.Event{Type: "persisted", TenantID: "t1", Data: []byte("durable")}); err != nil {
		t.Fatal(err)
	}
	if err := log1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	log2, err := events.Open(ctx, cfg) // same StoreDir
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer log2.Close()
	got := collect(t, log2, 0)
	if len(got) != 1 || string(got[0].Data) != "durable" {
		t.Fatalf("after reopen got %d events; want the durable one", len(got))
	}
}

// TestExternalModeIsConfigOnly proves switching to an external cluster is just a
// config change: an external-mode Log connects to a URL and works identically.
func TestExternalModeIsConfigOnly(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "external-test",
		JetStream:  true,
		StoreDir:   t.TempDir(),
		Port:       -1, // random available port
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("external server not ready")
	}
	defer srv.Shutdown()

	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL()})
	if err != nil {
		t.Fatalf("Open external: %v", err)
	}
	defer log.Close()

	if _, err := log.Append(ctx, events.Event{Type: "e", TenantID: "t1", Data: []byte("via-url")}); err != nil {
		t.Fatalf("Append (external): %v", err)
	}
	got := collect(t, log, 0)
	if len(got) != 1 || string(got[0].Data) != "via-url" {
		t.Fatalf("external replay = %d events; want 1", len(got))
	}
}
