package events_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
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
	t.Cleanup(func() { _ = log.Close() })
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
	defer func() { _ = log2.Close() }()
	got := collect(t, log2, 0)
	if len(got) != 1 || string(got[0].Data) != "durable" {
		t.Fatalf("after reopen got %d events; want the durable one", len(got))
	}
}

// TestEmbeddedStreamIsSingleReplica pins SPINE-004 for the embedded path: the
// in-process, single-node server creates the source-of-truth stream with exactly
// one replica (more than one is invalid on a single node), and a default-config
// embedded log still opens cleanly with the bounded fsync cadence (RESIL-001).
func TestEmbeddedStreamIsSingleReplica(t *testing.T) {
	ctx := context.Background()
	// Use the full default NATS config (embedded + the tightened SyncInterval) with
	// a temp store dir, so this also exercises the RESIL-001 default not breaking Open.
	cfg := config.Default().NATS
	cfg.StoreDir = t.TempDir()
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open embedded with defaults: %v", err)
	}
	defer func() { _ = log.Close() }()

	r, err := log.StreamReplicas(ctx)
	if err != nil {
		t.Fatalf("StreamReplicas: %v", err)
	}
	if r != 1 {
		t.Errorf("embedded stream replicas = %d, want 1", r)
	}
}

// TestExternalReplicasFallBackOnSingleNode pins SPINE-004: the external default
// replication factor is >1 (HA), but opening against a single, non-clustered NATS
// server must not fail — Open falls back to one replica. On the pre-fix tree the
// stream was always created with the implicit Replicas:1, so the *config knob* did
// not exist; here we prove the knob is honored (default >1) AND degrades safely.
func TestExternalReplicasFallBackOnSingleNode(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "ext-single", JetStream: true, StoreDir: t.TempDir(), Port: -1,
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
	// External mode with the default replication factor (3): a single-node server
	// rejects R>1, so Open must clamp to 1 rather than fail to start.
	cfg := config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL()}
	if config.DefaultExternalReplicas <= 1 {
		t.Fatalf("DefaultExternalReplicas = %d, want >1 (the knob this test guards)", config.DefaultExternalReplicas)
	}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open external (single-node, default replicas) must fall back, got: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, events.Event{Type: "e", TenantID: "t1", Data: []byte("x")}); err != nil {
		t.Fatalf("Append after fallback: %v", err)
	}
	r, err := log.StreamReplicas(ctx)
	if err != nil {
		t.Fatalf("StreamReplicas: %v", err)
	}
	if r != 1 {
		t.Errorf("single-node external stream replicas = %d, want 1 after fallback", r)
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
	defer func() { _ = log.Close() }()

	if _, err := log.Append(ctx, events.Event{Type: "e", TenantID: "t1", Data: []byte("via-url")}); err != nil {
		t.Fatalf("Append (external): %v", err)
	}
	got := collect(t, log, 0)
	if len(got) != 1 || string(got[0].Data) != "via-url" {
		t.Fatalf("external replay = %d events; want 1", len(got))
	}
}

// TestSchemaVersionStampedAndReplayed is the SCHEMA-001 envelope round-trip: an
// appended event is stamped with DefaultSchemaVersion when the producer leaves it
// zero, an explicit version is preserved verbatim, and both come back through
// Replay unchanged. Without the persisted "v" field the read model could not tell
// an old payload shape from a new one on a rebuild.
func TestSchemaVersionStampedAndReplayed(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()

	// A producer that does not set a version gets the baseline (v1) on append.
	e1, err := log.Append(ctx, events.Event{Type: "owner.created", TenantID: "t1", Data: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e1.SchemaVersion != events.DefaultSchemaVersion {
		t.Errorf("append left version unset; SchemaVersion = %d, want %d", e1.SchemaVersion, events.DefaultSchemaVersion)
	}

	// A producer evolving an existing type's payload sets the next version; it must
	// survive the round trip so a version-aware projector can dispatch on it.
	e2, err := log.Append(ctx, events.Event{Type: "owner.created", TenantID: "t1", SchemaVersion: 2, Data: []byte(`{}`)})
	if err != nil {
		t.Fatalf("Append v2: %v", err)
	}
	if e2.SchemaVersion != 2 {
		t.Errorf("explicit version not kept on append; SchemaVersion = %d, want 2", e2.SchemaVersion)
	}

	got := collect(t, log, 0)
	if len(got) != 2 {
		t.Fatalf("replayed %d events, want 2", len(got))
	}
	if got[0].SchemaVersion != events.DefaultSchemaVersion {
		t.Errorf("replayed event 1 SchemaVersion = %d, want %d", got[0].SchemaVersion, events.DefaultSchemaVersion)
	}
	if got[1].SchemaVersion != 2 {
		t.Errorf("replayed event 2 SchemaVersion = %d, want 2 (the producer's explicit version)", got[1].SchemaVersion)
	}
}

// TestLegacyEnvelopeReadsAsDefaultVersion proves an envelope persisted before the
// schema-version field existed (no "v" key on disk) reconstructs as
// DefaultSchemaVersion on Replay, not version 0 — so legacy events keep being
// treated as the baseline payload shape (SCHEMA-001 backward compatibility). A v1
// append writes "v" omitted (omitempty), byte-identical to a legacy envelope, so
// this pins the zero->baseline normalization the replay path performs.
func TestLegacyEnvelopeReadsAsDefaultVersion(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()
	if _, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: "t1", Data: []byte(`{"name":"x"}`)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got := collect(t, log, 0)
	if len(got) != 1 {
		t.Fatalf("replayed %d, want 1", len(got))
	}
	if got[0].SchemaVersion != events.DefaultSchemaVersion {
		t.Errorf("legacy (no-v) envelope replayed as version %d, want %d", got[0].SchemaVersion, events.DefaultSchemaVersion)
	}
}
