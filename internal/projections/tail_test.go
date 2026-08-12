// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestTailWorkerProjectsOutOfBandEvent is the SPINE-009 acceptance: an event
// appended out of band (directly to the log, NOT through the inline orchestrator
// projection) is projected by the durable tailing worker without a restart, and the
// projection-lag metric returns to zero once it catches up. On the pre-fix tree such
// an event was only projected on the next boot replay (silent lag) and there was no
// lag signal at all.
func TestTailWorkerProjectsOutOfBandEvent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proj := projections.New(s)

	// Seed a tenant so the owner projection's FK/RLS context is valid.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}

	// The lag sampler runs on its own goroutine (sampleLagLoop); count invocations
	// atomically so the read at the end of the test does not race the write from that
	// goroutine. The lag VALUE is timing-dependent and not asserted — only that the
	// gauge is actually sampled (SPINE-009).
	var sampled atomic.Uint64
	worker := projections.NewTailWorker(log, proj, func(float64) { sampled.Add(1) }, 50*time.Millisecond)
	runErr := make(chan error, 1)
	go func() { runErr <- worker.Run(ctx) }()

	// Append an owner event OUT OF BAND (the orchestrator did not project it inline).
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000c1", "tailed"),
	}); err != nil {
		t.Fatal(err)
	}

	// The tailing worker must project it within a short SLA, with no restart.
	deadline := time.Now().Add(20 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		got = ownerCount(t, s, tenantA)
		if got == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got != 1 {
		t.Fatalf("out-of-band event not projected by the tailing worker within SLA (owners=%d, want 1)", got)
	}

	// The lag must return to zero once caught up (the gauge exists and is exercised).
	lagDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(lagDeadline) {
		l, err := worker.Lag(ctx)
		if err != nil {
			t.Fatalf("Lag: %v", err)
		}
		if l == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if l, _ := worker.Lag(ctx); l != 0 {
		t.Errorf("projection lag = %d after catch-up, want 0", l)
	}
	if worker.Applied() == 0 {
		t.Error("worker Applied() is 0; the tailing worker did not advance its cursor")
	}
	// The lag gauge must actually be sampled (SPINE-009): the lag loop invokes the
	// sampler on its own 50ms cadence. Wait (bounded) for at least one invocation so
	// the assertion can't flake, then confirm the gauge is wired.
	sampledDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(sampledDeadline) && sampled.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if sampled.Load() == 0 {
		t.Error("lag sampler was never invoked; the SPINE-009 projection-lag gauge is not wired")
	}

	cancel()
	// Run returns the context error on shutdown — not a real failure.
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Error("tail worker did not stop on context cancel")
	}
}

// TestTailWorkerDurableCursorResumes is the SPINE-009 durability assertion: the
// consumer's cursor is server-side and durable, so a fresh worker (a "restart")
// resumes from the last applied event rather than re-projecting from the start. We
// project everything with worker #1, then start worker #2 and confirm it does not
// re-apply already-projected events (Applied advances only for genuinely new ones).
func TestTailWorkerDurableCursorResumes(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	proj := projections.New(s)

	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "one")}); err != nil {
		t.Fatal(err)
	}

	// Worker #1 drains everything, then stops.
	ctx1, cancel1 := context.WithCancel(ctx)
	w1 := projections.NewTailWorker(log, proj, nil, time.Second)
	done1 := make(chan struct{})
	go func() { defer close(done1); _ = w1.Run(ctx1) }()
	waitFor(t, func() bool { l, _ := w1.Lag(ctx); return l == 0 && w1.Applied() > 0 }, 20*time.Second, "worker #1 catch up")
	cancel1()
	<-done1

	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Worker #2 ("restart") must resume at the durable cursor: with no new events it
	// applies nothing and the lag is already zero.
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	w2 := projections.NewTailWorker(log, proj, nil, time.Second)
	done2 := make(chan struct{})
	go func() { defer close(done2); _ = w2.Run(ctx2) }()

	lagAfterRestart, err := w2.Lag(ctx)
	if err != nil {
		t.Fatalf("worker #2 lag after restart: %v", err)
	}
	if lagAfterRestart != 0 {
		t.Fatalf("worker #2 lag after restart with no new events = %d, want 0", lagAfterRestart)
	}
	if got := w2.Applied(); got != headBefore {
		t.Fatalf("worker #2 applied watermark after restart = %d, want persisted checkpoint/head %d", got, headBefore)
	}

	// Append one MORE event; only this one should be newly applied by worker #2.
	if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d2", "two")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return w2.Applied() > headBefore }, 20*time.Second, "worker #2 apply only the new event")
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Errorf("owners after resume = %d, want 2", got)
	}
	cancel2()
	<-done2
}

// TestTailWorkerSamplerStopsOnRunError is the SPINE-007 regression guard: a
// tail/apply error returns from one Run invocation, and that invocation's lag
// sampler must stop even while the parent service context remains live for the
// caller's retry loop.
func TestTailWorkerSamplerStopsOnRunError(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proj := projections.New(s)

	if _, err := log.Append(ctx, events.Event{
		Type:          projections.EventOwnerCreated,
		TenantID:      tenantA,
		SchemaVersion: 99, // unknown -> Apply rejects and TailWorker.Run returns
		Data:          ownerCreated("00000000-0000-0000-0000-0000000000e1", "poison"),
	}); err != nil {
		t.Fatal(err)
	}

	var sampled atomic.Uint64
	worker := projections.NewTailWorker(log, proj, func(float64) { sampled.Add(1) }, 10*time.Millisecond)
	if err := worker.Run(ctx); err == nil {
		t.Fatal("TailWorker.Run returned nil; want poison projection error")
	}

	before := sampled.Load()
	time.Sleep(80 * time.Millisecond)
	if after := sampled.Load(); after != before {
		t.Fatalf("lag sampler continued after TailWorker.Run returned: before=%d after=%d", before, after)
	}
}

// TestTailWorkerPersistsPoisonAndClearsItAfterRestart is the AUD-103 spine
// regression. A transient projection failure stops the first worker while a later
// event waits behind it. PostgreSQL retains the failed sequence after both the
// worker and file-backed JetStream restart. A healthy replacement replays the
// failed event, advances through it, clears the marker, and then drains the later
// event without another process restart.
func TestTailWorkerPersistsPoisonAndClearsItAfterRestart(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = 0, failed_seq = NULL, last_error = NULL,
		        failed_at = NULL, updated_at = now()
		  WHERE id = 1`); err != nil {
		t.Fatalf("reset projection-tail health: %v", err)
	}

	storeDir := t.TempDir()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir}
	log1, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open first file-backed log: %v", err)
	}

	poison := &switchableTailProjection{err: errors.New("transient extension poison")}
	proj1 := projections.New(s, projections.WithEventProjection(poison))
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant for extension poison: %v", err)
	}
	first, err := log1.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000f0", "poison"),
	})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log1.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000f1", "behind-poison"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := projections.NewTailWorker(log1, proj1, nil, time.Second).Run(ctx); err == nil {
		t.Fatal("first TailWorker.Run returned nil; want injected projection failure")
	}
	health, err := s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 0 || health.FailedSequence != first.Sequence ||
		!strings.Contains(health.LastError, "transient extension poison") || health.FailedAt == nil {
		t.Fatalf("poison was not persisted before Run returned: %+v", health)
	}
	if later.Sequence <= health.FailedSequence {
		t.Fatalf("test precondition: later seq=%d must wait behind poison seq=%d", later.Sequence, health.FailedSequence)
	}
	if err := log1.Close(); err != nil {
		t.Fatalf("close first file-backed log: %v", err)
	}

	// A second Store and Log are the process-restart boundary. Nothing is copied:
	// both PostgreSQL and JetStream reopen the durable state they already own.
	restartedStore, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("open restarted store: %v", err)
	}
	defer restartedStore.Close()
	if err := restartedStore.Migrate(ctx); err != nil {
		t.Fatalf("migrate restarted store: %v", err)
	}
	restartedHealth, err := restartedStore.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if restartedHealth.FailedSequence != first.Sequence || restartedHealth.LastError == "" {
		t.Fatalf("restart lost persisted poison: %+v", restartedHealth)
	}

	log2, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("reopen file-backed log: %v", err)
	}
	defer func() { _ = log2.Close() }()
	healthyProjection := &switchableTailProjection{}
	worker := projections.NewTailWorker(log2,
		projections.New(restartedStore, projections.WithEventProjection(healthyProjection)), nil, time.Second)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- worker.Run(runCtx) }()

	deadline := time.Now().Add(45 * time.Second)
	var lastHealth store.ProjectionTailHealth
	for time.Now().Before(deadline) {
		select {
		case runErr := <-done:
			t.Fatalf("restarted tail returned before recovery: %v (last health %+v)", runErr, lastHealth)
		default:
		}
		lastHealth, err = restartedStore.ProjectionTailHealth(ctx)
		if err == nil && lastHealth.AppliedSequence == later.Sequence &&
			lastHealth.FailedSequence == 0 && lastHealth.LastError == "" && lastHealth.FailedAt == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastHealth.AppliedSequence != later.Sequence || lastHealth.FailedSequence != 0 ||
		lastHealth.LastError != "" || lastHealth.FailedAt != nil {
		t.Fatalf("restarted tail did not clear poison and drain later event: %+v", lastHealth)
	}
	if got := ownerCount(t, restartedStore, tenantA); got != 2 {
		t.Fatalf("owners after recovered tail = %d, want 2", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("restarted tail worker did not stop")
	}
}

// TestTailWorkerPersistsMalformedEnvelopeFailure covers the failure boundary
// before the projector callback. A real external, file-backed JetStream accepts a
// malformed envelope directly; TailWorker must persist its stream sequence so a
// decode poison cannot leave readiness green while a later valid event waits.
func TestTailWorkerPersistsMalformedEnvelopeFailure(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	natsServer, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "aud103-malformed-envelope", JetStream: true,
		StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatalf("create external file-backed NATS: %v", err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(10 * time.Second) {
		natsServer.Shutdown()
		t.Fatal("external file-backed NATS did not become ready")
	}
	defer natsServer.Shutdown()

	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSExternal, URL: natsServer.ClientURL(),
		Replicas: 1, AllowSingleReplica: true,
	})
	if err != nil {
		t.Fatalf("open external file-backed event log: %v", err)
	}
	defer func() { _ = log.Close() }()

	rawConn, err := nats.Connect(natsServer.ClientURL())
	if err != nil {
		t.Fatalf("connect raw malformed-envelope publisher: %v", err)
	}
	defer rawConn.Close()
	rawJS, err := jetstream.New(rawConn)
	if err != nil {
		t.Fatalf("open raw JetStream publisher: %v", err)
	}
	ack, err := rawJS.Publish(ctx, "events.owner.created", []byte(`{"unterminated"`))
	if err != nil {
		t.Fatalf("publish malformed stored envelope: %v", err)
	}
	later, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("waits-behind-malformed"),
	})
	if err != nil {
		t.Fatalf("append later valid event: %v", err)
	}
	if later.Sequence <= ack.Sequence {
		t.Fatalf("test precondition: later seq=%d must follow malformed seq=%d", later.Sequence, ack.Sequence)
	}

	runErr := projections.NewTailWorker(log, projections.New(s), nil, time.Second).Run(ctx)
	if runErr == nil {
		t.Fatal("TailWorker.Run returned nil for malformed stored envelope")
	}
	var decodeErr *events.EnvelopeDecodeError
	if !errors.As(runErr, &decodeErr) || decodeErr.Sequence != ack.Sequence {
		t.Fatalf("TailWorker.Run error = %v, want EnvelopeDecodeError seq %d", runErr, ack.Sequence)
	}
	health, err := s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 0 || health.FailedSequence != ack.Sequence ||
		health.LastError == "" || health.FailedAt == nil {
		t.Fatalf("pre-callback decode poison was not persisted: %+v", health)
	}
}

type switchableTailProjection struct {
	err error
}

func (*switchableTailProjection) Name() string                { return "aud103-switchable" }
func (*switchableTailProjection) Reset(context.Context) error { return nil }
func (p *switchableTailProjection) Apply(context.Context, eventspec.Event) error {
	return p.err
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}
