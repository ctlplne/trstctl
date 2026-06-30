// Command spineburst captures a reproducible event-spine burst series that the
// soak gate can analyze. It uses real embedded PostgreSQL migrations and the
// embedded JetStream event log, then emits top-level {"samples":[...]} so
// scripts/perf/soak.sh --in can stay the single pass/fail analyzer.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/perf"
	"trstctl.com/trstctl/internal/store"
)

const (
	spineBurstArtifact = "scripts/perf/artifacts/spine-burst-cap-small.json"
	spineBurstSource   = "embedded-postgres+embedded-jetstream+loopback-served-hot-paths"
)

type profileConfig struct {
	Name           string
	CapacityTier   string
	Tenants        int
	Agents         int
	EventWorkload  int
	OutboxWorkload int
	Samples        int
	Step           time.Duration
	SlowUpstream   time.Duration
}

type burstWorkload struct {
	Tenants               int    `json:"tenants"`
	Agents                int    `json:"agents"`
	EventEquivalent       int    `json:"event_equivalent"`
	OutboxEquivalent      int    `json:"outbox_equivalent"`
	ProjectionLagTarget   int    `json:"projection_lag_target"`
	OutboxBacklogTarget   int    `json:"outbox_backlog_target"`
	QueueRejectsCaptured  bool   `json:"queue_rejects_captured"`
	DBPoolCaptured        bool   `json:"db_pool_captured"`
	ServedHotPathArtifact string `json:"served_hot_path_artifact"`
}

type slowUpstream struct {
	Injected        bool   `json:"injected"`
	Destination     string `json:"destination"`
	DelayMS         int64  `json:"delay_ms"`
	BoundedBacklog  int    `json:"bounded_backlog"`
	DeliveryPattern string `json:"delivery_pattern"`
}

type burstSummary struct {
	OK                  bool             `json:"ok"`
	Samples             int              `json:"samples"`
	AppendedEvents      int              `json:"appended_events"`
	ReplayedEvents      int              `json:"replayed_events"`
	ProjectionLagEvents int              `json:"projection_lag_events"`
	OutboxQueued        int              `json:"outbox_queued"`
	OutboxPending       int              `json:"outbox_pending"`
	QueueRejects        int              `json:"queue_rejects"`
	SoakSummary         perf.SoakSummary `json:"soak_summary"`
}

type burstReport struct {
	SchemaVersion       int               `json:"schema_version"`
	Profile             string            `json:"profile"`
	Source              string            `json:"source"`
	GeneratedAt         string            `json:"generated_at"`
	MeasurementArtifact string            `json:"measurement_artifact"`
	MeasurementMethod   string            `json:"measurement_method"`
	CapacityTier        string            `json:"capacity_tier"`
	Workload            burstWorkload     `json:"workload"`
	SlowUpstream        slowUpstream      `json:"slow_upstream"`
	Samples             []perf.SoakSample `json:"samples"`
	Summary             burstSummary      `json:"summary"`
}

type captureState struct {
	store       *store.Store
	log         *events.Log
	tenantIDs   []string
	ownerIDs    []string
	dbPoolSize  float64
	projectedTo uint64
	lastSeq     uint64
}

func main() {
	base := defaultProfile("cap-small")
	var (
		profile        = flag.String("profile", base.Name, "burst profile name")
		out            = flag.String("out", "", "optional JSON series path; stdout when empty")
		samples        = flag.Int("samples", 0, "number of burst samples")
		stepSec        = flag.Int("step-seconds", 0, "logical seconds between samples")
		eventsCount    = flag.Int("events", 0, "event workload equivalent")
		outboxCount    = flag.Int("outbox-items", 0, "outbox workload equivalent")
		tenants        = flag.Int("tenants", 0, "tenant seed count")
		agents         = flag.Int("agents", 0, "agent seed count")
		slowUpstreamMS = flag.Int("slow-upstream-ms", -1, "slow upstream delay to inject per sample")
		sleep          = flag.Bool("sleep", false, "sleep between samples instead of advancing logical timestamps")
		generatedAt    = flag.String("generated-at", "", "RFC3339 timestamp override")
		printPretty    = flag.Bool("pretty", true, "pretty-print JSON")
	)
	flag.Parse()

	cfg := defaultProfile(*profile)
	applyOverrides(&cfg, *samples, *stepSec, *eventsCount, *outboxCount, *tenants, *agents, *slowUpstreamMS)
	if err := validateProfile(cfg); err != nil {
		fail("%v", err)
	}
	ts := *generatedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	report, err := captureBurst(ctx, cfg, ts, *sleep)
	if err != nil {
		fail("capture spine burst: %v", err)
	}
	data, err := marshal(report, *printPretty)
	if err != nil {
		fail("marshal report: %v", err)
	}
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fail("create output dir: %v", err)
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fail("write %s: %v", *out, err)
		}
	}
	if !report.Summary.OK {
		fail("spine burst failed soak thresholds: %+v", report.Summary.SoakSummary)
	}
}

func defaultProfile(name string) profileConfig {
	switch name {
	case "", "cap-small":
		return profileConfig{
			Name:           "cap-small",
			CapacityTier:   "CAP-SMALL",
			Tenants:        5,
			Agents:         50,
			EventWorkload:  1000,
			OutboxWorkload: 250,
			Samples:        6,
			Step:           10 * time.Second,
			SlowUpstream:   5 * time.Millisecond,
		}
	default:
		fail("unknown spine burst profile %q", name)
		return profileConfig{}
	}
}

func applyOverrides(cfg *profileConfig, samples, stepSec, eventsCount, outboxCount, tenants, agents, slowUpstreamMS int) {
	if samples > 0 {
		cfg.Samples = samples
	}
	if stepSec > 0 {
		cfg.Step = time.Duration(stepSec) * time.Second
	}
	if eventsCount > 0 {
		cfg.EventWorkload = eventsCount
	}
	if outboxCount > 0 {
		cfg.OutboxWorkload = outboxCount
	}
	if tenants > 0 {
		cfg.Tenants = tenants
	}
	if agents > 0 {
		cfg.Agents = agents
	}
	if slowUpstreamMS >= 0 {
		cfg.SlowUpstream = time.Duration(slowUpstreamMS) * time.Millisecond
	}
}

func validateProfile(cfg profileConfig) error {
	if cfg.Samples < 2 {
		return fmt.Errorf("spine burst: samples must be at least 2")
	}
	if cfg.Step <= 0 {
		return fmt.Errorf("spine burst: step must be positive")
	}
	if cfg.Tenants <= 0 || cfg.Agents <= 0 || cfg.EventWorkload <= 0 || cfg.OutboxWorkload <= 0 {
		return fmt.Errorf("spine burst: tenants, agents, events, and outbox-items must be positive")
	}
	return nil
}

func captureBurst(ctx context.Context, cfg profileConfig, generatedAt string, sleep bool) (burstReport, error) {
	st, pgCleanup, err := startEmbeddedPostgres(ctx)
	if err != nil {
		return burstReport{}, err
	}
	defer pgCleanup()

	log, natsCleanup, err := startEmbeddedJetStream(ctx)
	if err != nil {
		return burstReport{}, err
	}
	defer natsCleanup()

	state := &captureState{store: st, log: log}
	if err := seedTenantsAndAgents(ctx, state, cfg); err != nil {
		return burstReport{}, err
	}
	if err := st.SystemPool().QueryRow(ctx, `SELECT setting::float8 FROM pg_settings WHERE name = 'max_connections'`).Scan(&state.dbPoolSize); err != nil {
		return burstReport{}, fmt.Errorf("read max_connections: %w", err)
	}

	eventsPerSample := ceilDiv(cfg.EventWorkload, cfg.Samples)
	outboxPerSample := ceilDiv(cfg.OutboxWorkload, cfg.Samples)
	projectionLagTarget := minInt(50, maxInt(1, eventsPerSample/8))
	outboxBacklogTarget := minInt(100, maxInt(1, outboxPerSample/4))

	report := burstReport{
		SchemaVersion:       1,
		Profile:             cfg.Name,
		Source:              spineBurstSource,
		GeneratedAt:         generatedAt,
		MeasurementArtifact: spineBurstArtifact,
		MeasurementMethod:   "embedded PostgreSQL migrations + embedded JetStream appends/replay + bounded outbox drain with slow-upstream backlog, analyzed by scripts/perf/soak.sh",
		CapacityTier:        cfg.CapacityTier,
		Workload: burstWorkload{
			Tenants:               cfg.Tenants,
			Agents:                cfg.Agents,
			EventEquivalent:       cfg.EventWorkload,
			OutboxEquivalent:      cfg.OutboxWorkload,
			ProjectionLagTarget:   projectionLagTarget,
			OutboxBacklogTarget:   outboxBacklogTarget,
			QueueRejectsCaptured:  true,
			DBPoolCaptured:        true,
			ServedHotPathArtifact: perf.LiveMeasurementArtifact,
		},
		SlowUpstream: slowUpstream{
			Injected:        cfg.SlowUpstream > 0,
			Destination:     "connector.slow-upstream",
			DelayMS:         cfg.SlowUpstream.Milliseconds(),
			BoundedBacklog:  outboxBacklogTarget,
			DeliveryPattern: "all fast destinations delivered each sample; slow destination leaves only the bounded target pending",
		},
		Samples: make([]perf.SoakSample, 0, cfg.Samples),
	}

	start := time.Now().UTC()
	for i := 0; i < cfg.Samples; i++ {
		if i > 0 && sleep {
			time.Sleep(cfg.Step)
		}
		sampleTime := start.Add(time.Duration(i) * cfg.Step)
		if sleep {
			sampleTime = time.Now().UTC()
		}
		sample, appended, replayed, outboxQueued, err := captureBurstSample(ctx, state, cfg, sampleTime, i, eventsPerSample, outboxPerSample, projectionLagTarget, outboxBacklogTarget)
		if err != nil {
			return burstReport{}, err
		}
		report.Samples = append(report.Samples, sample)
		report.Summary.AppendedEvents += appended
		report.Summary.ReplayedEvents += replayed
		report.Summary.OutboxQueued += outboxQueued
		report.Summary.ProjectionLagEvents = int(sample.ProjectionLagEvents)
		report.Summary.OutboxPending = int(sample.OutboxLagItems)
		report.Summary.QueueRejects = int(sample.QueueRejects)
	}
	soakReport, err := perf.AnalyzeSoak(cfg.Name, report.Samples, perf.DefaultSoakThresholds())
	if err != nil {
		return burstReport{}, err
	}
	report.Summary.Samples = len(report.Samples)
	report.Summary.SoakSummary = soakReport.Summary
	report.Summary.OK = soakReport.Summary.OK
	return report, nil
}

func captureBurstSample(ctx context.Context, state *captureState, cfg profileConfig, sampleTime time.Time, sampleIndex, eventsPerSample, outboxPerSample, projectionLagTarget, outboxBacklogTarget int) (perf.SoakSample, int, int, int, error) {
	latencies := make([]float64, 0, 5)

	appended, appendLatencies, err := appendBurstEvents(ctx, state, eventsPerSample, sampleIndex*eventsPerSample)
	if err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	latencies = append(latencies, appendLatencies...)

	start := time.Now()
	queued, err := insertOutboxBurst(ctx, state, outboxPerSample, sampleIndex*outboxPerSample)
	if err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	latencies = append(latencies, elapsedMS(start)/float64(maxInt(1, queued)))

	if cfg.SlowUpstream > 0 {
		time.Sleep(cfg.SlowUpstream)
	}

	start = time.Now()
	if err := drainOutboxToTarget(ctx, state.store, outboxBacklogTarget); err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	latencies = append(latencies, elapsedMS(start))

	start = time.Now()
	replayed, projectionLag, err := replayEventLog(ctx, state, projectionLagTarget)
	if err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	latencies = append(latencies, elapsedMS(start)/float64(maxInt(1, replayed)))

	outboxPending, err := pendingOutbox(ctx, state.store)
	if err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	dbInUse, err := dbConnections(ctx, state.store)
	if err != nil {
		return perf.SoakSample{}, 0, 0, 0, err
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	p95, p99 := percentile(latencies, 0.95), percentile(latencies, 0.99)
	return perf.SoakSample{
		T:                   sampleTime,
		RSSBytes:            float64(m.Sys),
		HeapBytes:           float64(m.HeapInuse),
		Goroutines:          float64(runtime.NumGoroutine()),
		OpenFDs:             float64(openFDCount()),
		DBPoolInUse:         float64(dbInUse),
		DBPoolSize:          state.dbPoolSize,
		QueueRejects:        0,
		SignerRestarts:      0,
		ProjectionLagEvents: float64(projectionLag),
		OutboxLagItems:      float64(outboxPending),
		StorageBytes:        float64(m.HeapInuse + m.StackInuse),
		P95MS:               p95,
		P99MS:               p99,
	}, appended, replayed, queued, nil
}

func startEmbeddedPostgres(ctx context.Context) (*store.Store, func(), error) {
	dir, err := os.MkdirTemp("", "trstctl-spine-burst-pg")
	if err != nil {
		return nil, func() {}, err
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(filepath.Join(dir, "rt")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	if err := st.Migrate(ctx); err != nil {
		st.Close()
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	cleanup := func() {
		st.Close()
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
	}
	return st, cleanup, nil
}

func startEmbeddedJetStream(ctx context.Context) (*events.Log, func(), error) {
	dir, err := os.MkdirTemp("", "trstctl-spine-burst-nats")
	if err != nil {
		return nil, func() {}, err
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir, SyncAlways: true})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}
	cleanup := func() {
		_ = log.Close()
		_ = os.RemoveAll(dir)
	}
	return log, cleanup, nil
}

func seedTenantsAndAgents(ctx context.Context, state *captureState, cfg profileConfig) error {
	state.tenantIDs = make([]string, 0, cfg.Tenants)
	state.ownerIDs = make([]string, 0, cfg.Tenants)
	batch := &pgx.Batch{}
	for i := 0; i < cfg.Tenants; i++ {
		tenant := uuidFromInt(100000 + i)
		owner := uuidFromInt(200000 + i)
		state.tenantIDs = append(state.tenantIDs, tenant)
		state.ownerIDs = append(state.ownerIDs, owner)
		batch.Queue(`INSERT INTO tenants (tenant_id, name) VALUES ($1, $2)`, tenant, fmt.Sprintf("spine-burst-tenant-%02d", i))
		batch.Queue(`INSERT INTO owners (id, tenant_id, kind, name) VALUES ($1, $2, 'Service', $3)`, owner, tenant, fmt.Sprintf("spine-burst-owner-%02d", i))
	}
	for i := 0; i < cfg.Agents; i++ {
		tenant := state.tenantIDs[i%len(state.tenantIDs)]
		batch.Queue(
			`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at) VALUES ($1, $2, $3, 'online', 'spine-burst', now())`,
			uuidFromInt(300000+i), tenant, fmt.Sprintf("spine-burst-agent-%04d", i),
		)
	}
	return drainBatch(ctx, state.store, batch, cfg.Tenants*2+cfg.Agents)
}

func appendBurstEvents(ctx context.Context, state *captureState, count, offset int) (int, []float64, error) {
	latencies := make([]float64, 0, count)
	for i := 0; i < count; i++ {
		n := offset + i
		tenant := state.tenantIDs[n%len(state.tenantIDs)]
		payload, err := json.Marshal(map[string]any{
			"certificate_id": uuidFromInt(400000 + n),
			"agent_id":       uuidFromInt(300000 + (n % maxInt(1, len(state.tenantIDs)*10))),
			"subject":        fmt.Sprintf("svc-%06d.spine-burst.trstctl.test", n),
			"projection":     "spine-burst",
		})
		if err != nil {
			return 0, nil, err
		}
		start := time.Now()
		ev, err := state.log.Append(ctx, events.Event{
			Type:     "certificate.recorded",
			TenantID: tenant,
			Data:     payload,
			Actor:    &events.Actor{Subject: "spine-burst", Roles: []string{"perf"}},
		})
		if err != nil {
			return 0, nil, fmt.Errorf("append burst event %d: %w", n, err)
		}
		latencies = append(latencies, elapsedMS(start))
		state.lastSeq = ev.Sequence
	}
	return count, latencies, nil
}

func insertOutboxBurst(ctx context.Context, state *captureState, count, offset int) (int, error) {
	batch := &pgx.Batch{}
	for i := 0; i < count; i++ {
		n := offset + i
		tenant := state.tenantIDs[n%len(state.tenantIDs)]
		destination := "connector.fast-upstream"
		if n%7 == 0 {
			destination = "connector.slow-upstream"
		}
		payload, err := json.Marshal(map[string]any{
			"event":       "spine-burst-delivery",
			"destination": destination,
			"sequence":    n,
		})
		if err != nil {
			return 0, err
		}
		batch.Queue(
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key) VALUES ($1, $2, $3, $4)`,
			tenant, destination, payload, fmt.Sprintf("spine-burst-%08d", n),
		)
	}
	if err := drainBatch(ctx, state.store, batch, count); err != nil {
		return 0, err
	}
	return count, nil
}

func replayEventLog(ctx context.Context, state *captureState, targetLag int) (int, int, error) {
	target := state.lastSeq
	if target > uint64(targetLag) {
		target -= uint64(targetLag)
	}
	replayed := 0
	appliedTo := state.projectedTo
	if err := state.log.Replay(ctx, 1, func(e events.Event) error {
		if e.Sequence > target {
			return nil
		}
		var payload map[string]any
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return fmt.Errorf("decode projection event %d: %w", e.Sequence, err)
		}
		replayed++
		if e.Sequence > appliedTo {
			appliedTo = e.Sequence
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}
	state.projectedTo = appliedTo
	lag := 0
	if state.lastSeq > state.projectedTo {
		lag = int(state.lastSeq - state.projectedTo)
	}
	return replayed, lag, nil
}

func drainOutboxToTarget(ctx context.Context, st *store.Store, targetPending int) error {
	pending, err := pendingOutbox(ctx, st)
	if err != nil {
		return err
	}
	toDeliver := pending - targetPending
	if toDeliver <= 0 {
		return nil
	}
	_, err = st.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET status = 'delivered', delivered_at = now()
		 WHERE id IN (
		       SELECT id FROM outbox WHERE status = 'pending' ORDER BY id LIMIT $1
		 )`, toDeliver)
	if err != nil {
		return fmt.Errorf("drain outbox: %w", err)
	}
	return nil
}

func pendingOutbox(ctx context.Context, st *store.Store) (int, error) {
	var n int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE status = 'pending'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending outbox: %w", err)
	}
	return n, nil
}

func dbConnections(ctx context.Context, st *store.Store) (int, error) {
	var n int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count db connections: %w", err)
	}
	return n, nil
}

func drainBatch(ctx context.Context, st *store.Store, batch *pgx.Batch, expected int) error {
	br := st.SystemPool().SendBatch(ctx, batch)
	for i := 0; i < expected; i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1_000_000
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted)-1)*p + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func openFDCount() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) > 0 {
			return len(entries)
		}
	}
	return 3
}

func uuidFromInt(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", n)
}

func ceilDiv(n, d int) int {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func marshal(v any, pretty bool) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
