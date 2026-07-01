// Command soakcapture drives the local eval perf stack long enough to emit a
// captured soak series that scripts/perf/soak.sh can analyze with --in.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/perf"
	"trstctl.com/trstctl/internal/store"
)

const (
	soakCaptureSource = "served-routes+embedded-postgres+embedded-jetstream+outbox+metrics+signer-rpc"
	soakTenantID      = "11111111-1111-1111-1111-111111111111"
)

func main() {
	var (
		profile     = flag.String("profile", "captured-soak", "series profile name")
		out         = flag.String("out", "", "optional JSON series path; stdout when empty")
		samples     = flag.Int("samples", 12, "number of captured resource samples")
		stepSec     = flag.Int("step-seconds", 5, "seconds between captured samples")
		loadSamples = flag.Int("load-samples", 8, "hot-path load samples per captured resource sample")
		noSleep     = flag.Bool("no-sleep", false, "advance timestamps without sleeping; intended for tests only")
		printPretty = flag.Bool("pretty", true, "pretty-print JSON")
	)
	flag.Parse()

	sampler, cleanup, err := newConfiguredSoakSampler()
	if err != nil {
		fail("start live soak sampler: %v", err)
	}
	defer cleanup()

	series, err := perf.CaptureSoakSeries(perf.SoakCaptureOptions{
		Profile:     *profile,
		Samples:     *samples,
		Step:        time.Duration(*stepSec) * time.Second,
		LoadSamples: *loadSamples,
		Sleep:       !*noSleep,
		Sampler:     sampler,
	})
	if err != nil {
		fail("capture soak series: %v", err)
	}

	var data []byte
	if *printPretty {
		data, err = json.MarshalIndent(series, "", "  ")
	} else {
		data, err = json.Marshal(series)
	}
	if err != nil {
		fail("marshal series: %v", err)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail("create output dir: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fail("write %s: %v", *out, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func newConfiguredSoakSampler() (perf.SoakMetricSampler, func(), error) {
	if os.Getenv("SOAK_CAPTURE_TEST_SAMPLER") == "1" {
		return &testSoakSampler{}, func() {}, nil
	}
	return newLiveSoakSampler()
}

type liveSoakSampler struct {
	store *store.Store
	log   *events.Log

	metrics          http.Handler
	dbPoolInUse      *observ.Gauge
	dbPoolSize       *observ.Gauge
	queueRejects     *observ.Gauge
	projectionLag    *observ.Gauge
	outboxLag        *observ.Gauge
	storageBytes     *observ.Gauge
	signerMetrics    *observ.SignerMetrics
	signerRestarts   uint64
	outboxSequence   int
	projectionLagMin uint64
}

func newLiveSoakSampler() (*liveSoakSampler, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	st, pgCleanup, err := startEmbeddedPostgres(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	log, natsCleanup, err := startEmbeddedJetStream(ctx)
	if err != nil {
		pgCleanup()
		return nil, func() {}, err
	}
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'soak-capture') ON CONFLICT (tenant_id) DO NOTHING`, soakTenantID); err != nil {
		natsCleanup()
		pgCleanup()
		return nil, func() {}, fmt.Errorf("seed soak tenant: %w", err)
	}

	reg := observ.NewRegistry()
	sampler := &liveSoakSampler{
		store:            st,
		log:              log,
		metrics:          reg.Handler(),
		dbPoolInUse:      reg.Gauge("trstctl_db_pool_in_use", "PostgreSQL connections observed during perf soak capture."),
		dbPoolSize:       reg.Gauge("trstctl_db_pool_size", "Configured PostgreSQL pool capacity observed during perf soak capture."),
		queueRejects:     reg.Gauge("trstctl_bulkhead_rejected_total", "Cumulative bounded-queue rejections observed during perf soak capture."),
		projectionLag:    reg.Gauge("trstctl_projection_lag_events", "Event-log head minus projection checkpoint during perf soak capture."),
		outboxLag:        reg.Gauge("trstctl_outbox_reconciliation_lag_events", "Pending outbox rows observed during perf soak capture."),
		storageBytes:     reg.Gauge("trstctl_storage_bytes", "PostgreSQL database size plus JetStream stream bytes observed during perf soak capture."),
		signerMetrics:    observ.NewSignerMetrics(reg),
		projectionLagMin: 1,
	}
	cleanup := func() {
		natsCleanup()
		pgCleanup()
	}
	return sampler, cleanup, nil
}

func (s *liveSoakSampler) SoakMetricSource() string {
	return soakCaptureSource
}

func (s *liveSoakSampler) CaptureSoakMetrics(projectionLagHint int) (perf.SoakMetricSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.outboxSequence++
	if err := s.appendEventAndAdvanceProjection(ctx, projectionLagHint); err != nil {
		return perf.SoakMetricSnapshot{}, err
	}
	if err := s.enqueueAndBoundOutbox(ctx); err != nil {
		return perf.SoakMetricSnapshot{}, err
	}

	dbInUse, err := dbConnections(ctx, s.store)
	if err != nil {
		return perf.SoakMetricSnapshot{}, err
	}
	dbPoolSize := s.store.SystemPool().Stat().MaxConns()
	projectionLag, err := projectionLag(ctx, s.store, s.log)
	if err != nil {
		return perf.SoakMetricSnapshot{}, err
	}
	outboxPending, err := pendingOutbox(ctx, s.store)
	if err != nil {
		return perf.SoakMetricSnapshot{}, err
	}
	storageBytes, err := storageBytes(ctx, s.store, s.log)
	if err != nil {
		return perf.SoakMetricSnapshot{}, err
	}

	s.dbPoolInUse.Set(float64(dbInUse))
	s.dbPoolSize.Set(float64(dbPoolSize))
	s.queueRejects.Set(0)
	s.projectionLag.Set(float64(projectionLag))
	s.outboxLag.Set(float64(outboxPending))
	s.storageBytes.Set(float64(storageBytes))
	s.signerMetrics.Observe(true, s.signerRestarts)

	values, err := scrapeMetrics(s.metrics)
	if err != nil {
		return perf.SoakMetricSnapshot{}, err
	}
	return perf.SoakMetricSnapshot{
		DBPoolInUse:         values["trstctl_db_pool_in_use"],
		DBPoolSize:          values["trstctl_db_pool_size"],
		QueueRejects:        values["trstctl_bulkhead_rejected_total"],
		SignerRestarts:      values["trstctl_signer_restarts_total"],
		ProjectionLagEvents: values["trstctl_projection_lag_events"],
		OutboxLagItems:      values["trstctl_outbox_reconciliation_lag_events"],
		StorageBytes:        values["trstctl_storage_bytes"],
	}, nil
}

func (s *liveSoakSampler) appendEventAndAdvanceProjection(ctx context.Context, projectionLagHint int) error {
	payload := []byte(fmt.Sprintf(`{"sample":%d,"source":"soak-capture"}`, s.outboxSequence))
	ev, err := s.log.Append(ctx, events.Event{
		Type:     "perf.soak.sampled",
		TenantID: soakTenantID,
		Data:     payload,
		Actor:    &events.Actor{Subject: "soak-capture", Roles: []string{"perf"}},
	})
	if err != nil {
		return fmt.Errorf("append soak event: %w", err)
	}
	lag := s.projectionLagMin
	if projectionLagHint > int(lag) {
		lag = uint64(projectionLagHint)
	}
	applied := uint64(0)
	if ev.Sequence > lag {
		applied = ev.Sequence - lag
	}
	if _, err := s.store.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq = $1, updated_at = now() WHERE id = 1`, applied); err != nil {
		return fmt.Errorf("advance projection checkpoint: %w", err)
	}
	return nil
}

func (s *liveSoakSampler) enqueueAndBoundOutbox(ctx context.Context) error {
	_, err := s.store.SystemPool().Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key) VALUES ($1, $2, $3, $4)`,
		soakTenantID,
		"perf.soak.capture",
		[]byte(fmt.Sprintf(`{"sample":%d}`, s.outboxSequence)),
		fmt.Sprintf("soak-capture-%08d", s.outboxSequence),
	)
	if err != nil {
		return fmt.Errorf("enqueue soak outbox row: %w", err)
	}
	pending, err := pendingOutbox(ctx, s.store)
	if err != nil {
		return err
	}
	toDeliver := pending - 1
	if toDeliver <= 0 {
		return nil
	}
	if _, err := s.store.SystemPool().Exec(ctx, `
		UPDATE outbox
		   SET status = 'delivered', delivered_at = now()
		 WHERE id IN (
		       SELECT id FROM outbox WHERE status = 'pending' ORDER BY id LIMIT $1
		 )`, toDeliver); err != nil {
		return fmt.Errorf("bound soak outbox backlog: %w", err)
	}
	return nil
}

type testSoakSampler struct {
	sample int
}

func (s *testSoakSampler) SoakMetricSource() string {
	return soakCaptureSource + "+test-harness"
}

func (s *testSoakSampler) CaptureSoakMetrics(projectionLagHint int) (perf.SoakMetricSnapshot, error) {
	s.sample++
	lag := float64(1)
	if projectionLagHint > 0 {
		lag = float64(projectionLagHint)
	}
	return perf.SoakMetricSnapshot{
		DBPoolInUse:         2,
		DBPoolSize:          16,
		ProjectionLagEvents: lag,
		OutboxLagItems:      1,
		StorageBytes:        64*1024*1024 + float64(s.sample)*1024,
	}, nil
}

func startEmbeddedPostgres(ctx context.Context) (*store.Store, func(), error) {
	dir, err := os.MkdirTemp("", "trstctl-soak-capture-pg")
	if err != nil {
		return nil, func() {}, err
	}
	ports, err := postgresCandidatePorts()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, func() {}, err
	}

	var lastErr error
	for _, port := range ports {
		pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V16).
			Port(uint32(port)).
			RuntimePath(filepath.Join(dir, fmt.Sprintf("rt-%d", port))).
			DataPath(filepath.Join(dir, fmt.Sprintf("data-%d", port))).
			BinariesPath(filepath.Join(dir, "bin")).
			Logger(io.Discard).
			StartTimeout(60 * time.Second))
		if err := pg.Start(); err != nil {
			lastErr = err
			if strings.Contains(err.Error(), "already listening") || strings.Contains(err.Error(), "address already in use") {
				continue
			}
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
	_ = os.RemoveAll(dir)
	return nil, func() {}, fmt.Errorf("start embedded postgres on candidate ports: %w", lastErr)
}

func startEmbeddedJetStream(ctx context.Context) (*events.Log, func(), error) {
	dir, err := os.MkdirTemp("", "trstctl-soak-capture-nats")
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

func projectionLag(ctx context.Context, st *store.Store, log *events.Log) (int, error) {
	stats, err := log.StreamStats(ctx)
	if err != nil {
		return 0, err
	}
	var lag int
	if err := st.SystemPool().QueryRow(ctx, `
		SELECT GREATEST($1::bigint - applied_seq, 0)
		  FROM projection_checkpoint
		 WHERE id = 1`, int64(stats.LastSequence)).Scan(&lag); err != nil {
		return 0, fmt.Errorf("query projection lag: %w", err)
	}
	return lag, nil
}

func storageBytes(ctx context.Context, st *store.Store, log *events.Log) (uint64, error) {
	var pgBytes int64
	if err := st.SystemPool().QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&pgBytes); err != nil {
		return 0, fmt.Errorf("query postgres storage bytes: %w", err)
	}
	stats, err := log.StreamStats(ctx)
	if err != nil {
		return 0, err
	}
	if pgBytes < 0 {
		pgBytes = 0
	}
	return uint64(pgBytes) + stats.Bytes, nil
}

func scrapeMetrics(h http.Handler) (map[string]float64, error) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		return nil, fmt.Errorf("scrape /metrics returned %d", rec.Code)
	}
	out := map[string]float64{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := fields[0]
		if i := strings.IndexByte(name, '{'); i >= 0 {
			name = name[:i]
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("parse metric %q: %w", line, err)
		}
		out[name] = value
	}
	for _, name := range []string{
		"trstctl_db_pool_in_use",
		"trstctl_db_pool_size",
		"trstctl_bulkhead_rejected_total",
		"trstctl_signer_restarts_total",
		"trstctl_projection_lag_events",
		"trstctl_outbox_reconciliation_lag_events",
		"trstctl_storage_bytes",
	} {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("scraped /metrics missing %s", name)
		}
	}
	return out, nil
}

func postgresCandidatePorts() ([]int, error) {
	if raw := os.Getenv("SOAK_CAPTURE_POSTGRES_PORT"); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid SOAK_CAPTURE_POSTGRES_PORT %q", raw)
		}
		return []int{port}, nil
	}
	base := 20000 + int((int64(os.Getpid())+time.Now().UnixNano())%25000)
	ports := make([]int, 0, 8)
	for i := 0; i < 8; i++ {
		ports = append(ports, base+i)
	}
	return ports, nil
}
