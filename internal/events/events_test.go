// SPDX-License-Identifier: MPL-2.0

package events_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/schedulerhistory"
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

func TestJetStreamDuplicateMemoryReallyExpires(t *testing.T) {
	const duplicateWindow = 100 * time.Millisecond // JetStream's supported minimum.
	log, err := events.Open(context.Background(), embeddedCfg(t),
		events.WithDuplicateWindowForTesting(duplicateWindow))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event := events.Event{
		ID: "finite-dedup-window", Type: "test.finite.dedupe", TenantID: "tenant-a",
		Time: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), Data: []byte("same bytes"),
	}
	first, err := log.Append(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * duplicateWindow)
	second, err := log.Append(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence == first.Sequence {
		t.Fatalf("JetStream still deduplicated after %s: both sequence %d", duplicateWindow, first.Sequence)
	}
	if got := len(collect(t, log, 0)); got != 2 {
		t.Fatalf("retained events after duplicate-memory expiry = %d, want 2", got)
	}
}

func TestEventByIDAcceptsExactRetainedDuplicatesAndRejectsConflicts(t *testing.T) {
	const duplicateWindow = 100 * time.Millisecond
	log, err := events.Open(context.Background(), embeddedCfg(t),
		events.WithDuplicateWindowForTesting(duplicateWindow))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	ctx := context.Background()
	event := events.Event{
		ID: "event-by-id-finite-dedupe", Type: "test.event-by-id", TenantID: "tenant-a",
		Time: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC), Data: []byte("canonical"),
		Actor: &events.Actor{Subject: "producer-a", Roles: []string{"operator"}},
	}
	first, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * duplicateWindow)
	second, err := log.Append(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence == first.Sequence {
		t.Fatalf("exact duplicate remained inside finite broker window at sequence %d", first.Sequence)
	}
	canonical, found, err := log.EventByID(ctx, event.ID)
	if err != nil || !found || canonical.Sequence != first.Sequence ||
		!reflect.DeepEqual(canonical.Actor, event.Actor) || !reflect.DeepEqual(canonical.Data, event.Data) {
		t.Fatalf("exact retained duplicate lookup = (found=%t err=%v event=%+v)", found, err, canonical)
	}

	time.Sleep(4 * duplicateWindow)
	conflict := event
	conflict.Data = []byte("changed-command")
	if _, err := log.Append(ctx, conflict); err != nil {
		t.Fatal(err)
	}
	if _, found, err := log.EventByID(ctx, event.ID); !found || !errors.Is(err, events.ErrConflictingEventIdentity) {
		t.Fatalf("conflicting retained duplicate lookup = (found=%t err=%v), want ErrConflictingEventIdentity", found, err)
	}
}

func TestStreamStatsReportsLiveJetStreamCounters(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()

	if _, err := log.Append(ctx, events.Event{Type: "tenant.registered", TenantID: "t1", Data: []byte("x")}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{Type: "tenant.updated", TenantID: "t1", Data: []byte("yy")}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	stats, err := log.StreamStats(ctx)
	if err != nil {
		t.Fatalf("StreamStats: %v", err)
	}
	if stats.Messages != 2 || stats.LastSequence != 2 {
		t.Fatalf("StreamStats messages/last = %d/%d, want 2/2", stats.Messages, stats.LastSequence)
	}
	if stats.Bytes == 0 {
		t.Fatal("StreamStats bytes = 0, want live JetStream byte counter")
	}
}

func TestImportPreservesEnvelopeAndSuppressesDuplicateRetry(t *testing.T) {
	log := openEmbedded(t)
	ctx := context.Background()
	sourceTime := time.Unix(1700000000, 0).UTC()
	source := events.Event{
		ID: "fed-event-1", Type: "issuer.created", TenantID: "t1",
		Time: sourceTime, SchemaVersion: 2, Data: []byte(`{"id":"issuer-1"}`),
	}
	imported, err := log.Import(ctx, source)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	changedRetry := source
	changedRetry.Time = sourceTime.Add(time.Hour)
	changedRetry.Data = []byte(`{"id":"attacker-changed-retry"}`)
	retry, err := log.Import(ctx, changedRetry)
	if err != nil {
		t.Fatalf("retry Import: %v", err)
	}
	if retry.Sequence != imported.Sequence {
		t.Fatalf("duplicate import sequence = %d, want original sequence %d", retry.Sequence, imported.Sequence)
	}
	if !retry.Time.Equal(imported.Time) || !reflect.DeepEqual(retry.Data, imported.Data) {
		t.Fatalf("duplicate append returned retry bytes/time instead of canonical event: %+v", retry)
	}

	got := collect(t, log, 0)
	if len(got) != 1 {
		t.Fatalf("imported events = %d, want 1 duplicate-suppressed event", len(got))
	}
	if got[0].ID != source.ID || got[0].Type != source.Type || got[0].TenantID != source.TenantID || !got[0].Time.Equal(sourceTime) {
		t.Fatalf("imported envelope = %+v, want source identity/time preserved", got[0])
	}
	if got[0].SchemaVersion != 2 || !reflect.DeepEqual(got[0].Data, source.Data) {
		t.Fatalf("imported schema/data = v%d %q, want v2 %q", got[0].SchemaVersion, got[0].Data, source.Data)
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

// TestExternalReplicasStrictModeFailsOnSingleNode pins RESIL-004: the external
// default replication factor is >1 (HA), and opening against a single,
// non-clustered NATS server must fail closed rather than silently downgrade the
// source-of-truth event log to one replica.
func TestExternalReplicasStrictModeFailsOnSingleNode(t *testing.T) {
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
	// rejects R>1, so Open must fail rather than serve with weaker durability.
	cfg := config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL()}
	if config.DefaultExternalReplicas <= 1 {
		t.Fatalf("DefaultExternalReplicas = %d, want >1 (the knob this test guards)", config.DefaultExternalReplicas)
	}
	log, err := events.Open(ctx, cfg)
	if err == nil {
		_ = log.Close()
		t.Fatal("Open external (single-node, default replicas) succeeded; want strict durability failure")
	}
	if !strings.Contains(err.Error(), "requested 3 replicas") || !strings.Contains(err.Error(), "not clustered") {
		t.Fatalf("Open error = %v, want clear non-clustered replica failure", err)
	}
}

// TestExternalSingleReplicaRequiresExplicitAllow keeps local evaluation usable
// without weakening production: an external single-node JetStream works only when
// both the replica count and the eval-only allow flag are explicit.
func TestExternalSingleReplicaRequiresExplicitAllow(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "ext-single-allowed", JetStream: true, StoreDir: t.TempDir(), Port: -1,
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
	_, err = events.Open(ctx, config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL(), Replicas: 1})
	if err == nil {
		t.Fatal("Open external Replicas=1 without allow flag succeeded; want eval opt-in failure")
	}
	if !strings.Contains(err.Error(), "TRSTCTL_NATS_ALLOW_SINGLE_REPLICA") {
		t.Fatalf("Open error = %v, want explicit allow-single-replica guidance", err)
	}

	log, err := events.Open(ctx, config.NATS{
		Mode:               config.NATSExternal,
		URL:                srv.ClientURL(),
		Replicas:           1,
		AllowSingleReplica: true,
	})
	if err != nil {
		t.Fatalf("Open external eval single-replica: %v", err)
	}
	defer func() { _ = log.Close() }()
	if err := log.Ping(ctx); err != nil {
		t.Fatalf("Ping eval single-replica: %v", err)
	}
	status, err := log.StreamReplicaStatus(ctx)
	if err != nil {
		t.Fatalf("StreamReplicaStatus: %v", err)
	}
	if status.Actual != 1 || status.Desired != 1 || status.Degraded {
		t.Fatalf("replica status = %+v, want actual=desired=1 and not degraded", status)
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
	log, err := events.Open(ctx, config.NATS{
		Mode:               config.NATSExternal,
		URL:                srv.ClientURL(),
		Replicas:           1,
		AllowSingleReplica: true,
	})
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

func TestLegacySchedulerWriteFloorRequiresUnforgeableRestoreAuthority(t *testing.T) {
	key := []byte("scheduler-history-restore-authority-key")
	authorizer, err := crypto.NewBackupRestoreAuthorizer(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	log, err := events.Open(
		context.Background(), embeddedCfg(t),
		events.WithBackupRestoreAuthorizer(authorizer),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	log.EnforceLegacySchedulerWriteFloor()
	event := events.Event{
		ID: "legacy-scheduler-event", Type: schedulerhistory.EventType,
		TenantID: "11111111-1111-1111-1111-111111111111", SchemaVersion: 1,
		Time: time.Now().UTC(),
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"provider secret"}`),
	}
	if _, err := log.Append(context.Background(), event); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("Append error = %v, want sanitation-required", err)
	}
	if _, err := log.Import(context.Background(), event); !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
		t.Fatalf("Import error = %v, want sanitation-required", err)
	}
	history, err := events.LegacyBackupHistoryRecord(context.Background(), 1, event)
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := crypto.SHA256Hex([]byte("verified backup artifact"))
	source := func(yield func(events.BackupHistoryRecord) error) error { return yield(history) }
	if _, err := log.RestoreBackupHistory(context.Background(), 1, artifactDigest,
		func(yield func(events.BackupHistoryRecord) error) error { return yield(history) }); !errors.Is(err, events.ErrBackupRestoreAuthorizationRequired) {
		t.Fatalf("unguarded restore error = %v, want authorization-required", err)
	}
	historyDigest, err := events.BackupHistoryDigest(context.Background(), 1, source)
	if err != nil {
		t.Fatal(err)
	}
	intent := crypto.BackupRestoreIntent{
		EventCutSequence: 1,
		ArtifactSHA256:   artifactDigest,
		HistorySHA256:    historyDigest,
	}
	grant, err := crypto.BackupRestoreAuthorization(key, intent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Destroy)
	wrongGrant, err := crypto.BackupRestoreAuthorization(
		[]byte("wrong-scheduler-history-authority"), intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongGrant.Destroy)
	if _, err := log.RestoreAuthorizedBackupHistory(
		context.Background(), 1, intent.ArtifactSHA256, wrongGrant, source,
	); !errors.Is(err, events.ErrBackupRestoreAuthorizationRequired) {
		t.Fatalf("wrong-key restore grant error = %v, want authorization-required", err)
	}
	transplantedEvent := event
	transplantedEvent.ID = "transplanted-legacy-scheduler-event"
	transplantedEvent.Data = []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"different provider secret"}`)
	transplantedHistory, err := events.LegacyBackupHistoryRecord(
		context.Background(), 1, transplantedEvent,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.RestoreAuthorizedBackupHistory(
		context.Background(), 1, intent.ArtifactSHA256, grant,
		func(yield func(events.BackupHistoryRecord) error) error { return yield(transplantedHistory) },
	); !errors.Is(err, events.ErrBackupRestoreAuthorizationRequired) {
		t.Fatalf("transplanted restore source error = %v, want authorization-required", err)
	}
	if pristine, err := log.BackupHistoryPristine(context.Background()); err != nil || !pristine {
		t.Fatalf("rejected restore mutated target: pristine=%t err=%v", pristine, err)
	}
	if _, err := log.RestoreAuthorizedBackupHistory(
		context.Background(), 1, intent.ArtifactSHA256, grant, source,
	); err != nil {
		t.Fatalf("authorized exact restore rejected historical event: %v", err)
	}
}

func TestEventByIDNeverReturnsUnsafeLegacySchedulerPayload(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"provider secret"}`),
		[]byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":7}`),
	} {
		log := openEmbedded(t)
		appended, err := log.Append(context.Background(), events.Event{
			Type: schedulerhistory.EventType, TenantID: "11111111-1111-1111-1111-111111111111",
			SchemaVersion: 1, Data: data,
		})
		if err != nil {
			t.Fatal(err)
		}
		got, found, err := log.EventByID(context.Background(), appended.ID)
		if !errors.Is(err, schedulerhistory.ErrSanitationRequired) {
			t.Fatalf("EventByID error = %v, want sanitation-required", err)
		}
		if found || len(got.Data) != 0 {
			t.Fatalf("EventByID returned unsafe envelope: found=%v event=%#v", found, got)
		}
	}
}

func TestEventByIDUnsafeLegacyPayloadWinsOverDuplicateConflict(t *testing.T) {
	const duplicateWindow = 100 * time.Millisecond
	log, err := events.Open(
		context.Background(), embeddedCfg(t),
		events.WithDuplicateWindowForTesting(duplicateWindow),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	secret := "provider-credential-in-conflicting-history"
	event := events.Event{
		ID: "unsafe-conflicting-scheduler-event", Type: schedulerhistory.EventType,
		TenantID: "11111111-1111-1111-1111-111111111111", SchemaVersion: 1,
		Time: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC),
		Data: []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secret + `"}`),
	}
	if _, err := log.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * duplicateWindow)
	conflict := event
	conflict.Data = []byte(`{"schedule_id":"schedule-1","run_id":"run-2","status":"failed","error":"different provider detail"}`)
	if _, err := log.Append(context.Background(), conflict); err != nil {
		t.Fatal(err)
	}
	got, found, err := log.EventByID(context.Background(), event.ID)
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) ||
		!errors.Is(err, events.ErrConflictingEventIdentity) {
		t.Fatalf("EventByID conflict error = %v, want sanitation and conflict sentinels", err)
	}
	if found || len(got.Data) != 0 || strings.Contains(err.Error(), secret) {
		t.Fatalf("EventByID disclosed unsafe conflict: found=%v event=%#v err=%v", found, got, err)
	}
}

func TestLegacySchedulerReadFloorPreflightsReplayAndExportBeforeCallbacks(t *testing.T) {
	log := openEmbedded(t)
	secret := "provider-credential-late-in-history"
	if _, err := log.Append(context.Background(), events.Event{
		Type: "unrelated.event", TenantID: "11111111-1111-1111-1111-111111111111",
		Data: []byte(`{"safe":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	unsafe, err := log.Append(context.Background(), events.Event{
		Type: schedulerhistory.EventType, TenantID: "11111111-1111-1111-1111-111111111111",
		SchemaVersion: 1,
		Data:          []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"` + secret + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	log.EnforceLegacySchedulerWriteFloor()

	replayed := 0
	err = log.Replay(context.Background(), unsafe.Sequence+1, func(events.Event) error {
		replayed++
		return nil
	})
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) || replayed != 0 ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("Replay floor = callbacks:%d err:%v", replayed, err)
	}
	exported := 0
	err = log.ExportBackupHistoryThrough(
		context.Background(), unsafe.Sequence,
		func(events.BackupHistoryRecord) error {
			exported++
			return nil
		},
	)
	if !errors.Is(err, schedulerhistory.ErrSanitationRequired) || exported != 0 ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("Export floor = callbacks:%d err:%v", exported, err)
	}
}
