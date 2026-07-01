package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/perf"
	"trstctl.com/trstctl/internal/store"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	ownerID  = "00000000-0000-4000-8000-000000000001"

	requiredLiveStackProfile = "eval-loopback-production-served-routes"
)

type postgresMeasurement struct {
	certificateBytesTotal  int64
	certificateBytesPerRow int64
	credentialBytesTotal   int64
	credentialBytesPerRow  int64
	connections            int
}

type jetStreamMeasurement struct {
	bytesTotal    int64
	bytesPerEvent int64
}

func main() {
	out := flag.String("out", perf.CapacityMeasurementArtifact, "capacity calibration JSON output path")
	liveArtifact := flag.String("live-artifact", perf.LiveMeasurementArtifact, "served live-load artifact to read resource counters from")
	samples := flag.Int("samples", 1000, "rows/events to measure")
	generatedAt := flag.String("generated-at", "", "RFC3339 timestamp override")
	pretty := flag.Bool("pretty", true, "pretty-print JSON")
	flag.Parse()

	if *samples <= 0 {
		fail("samples must be positive")
	}
	ts := *generatedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pg, err := measurePostgres(ctx, *samples)
	if err != nil {
		fail("measure postgres: %v", err)
	}
	jetStream, err := measureJetStream(ctx, *samples)
	if err != nil {
		fail("measure jetstream: %v", err)
	}
	auditRecordBytes, err := measureAuditRecordBytes()
	if err != nil {
		fail("measure audit record: %v", err)
	}
	resources, err := measureResources(*liveArtifact, pg.connections)
	if err != nil {
		fail("measure live resources: %v", err)
	}

	costModel := perf.DefaultCapacityCostModel()
	report := perf.CapacityMeasurementReport{
		SchemaVersion:       1,
		Profile:             "capacity-calibration",
		GeneratedAt:         ts,
		MeasurementArtifact: perf.CapacityMeasurementArtifact,
		MeasurementMethod:   "embedded PostgreSQL pg_total_relation_size deltas, embedded JetStream file-store deltas, and committed served live-load resource counters",
		SourceArtifacts:     []string{perf.MeasurementArtifact, perf.LiveMeasurementArtifact},
		SampleSize:          *samples,
		StorageMeasurements: []perf.CapacityStorageMeasurement{
			{
				ID: "postgres_certificate_row", Unit: "certificate read-model row with indexes", Surface: "PostgreSQL certificates table",
				MeasurementSource: "pg_total_relation_size('certificates') after inserting representative certificate rows",
				Samples:           *samples, PostgresRelationBytes: pg.certificateBytesTotal,
				BytesPerUnit: pg.certificateBytesPerRow, HeadroomMultiplier: costModel.HeadroomMultiplier,
			},
			{
				ID: "postgres_credential_row", Unit: "sealed credential row with unique tenant index", Surface: "PostgreSQL credentials table",
				MeasurementSource: "pg_total_relation_size('credentials') after inserting representative sealed credential rows",
				Samples:           *samples, PostgresRelationBytes: pg.credentialBytesTotal,
				BytesPerUnit: pg.credentialBytesPerRow, HeadroomMultiplier: costModel.HeadroomMultiplier,
			},
			{
				ID: "jetstream_event", Unit: "event envelope in embedded JetStream file store", Surface: "NATS JetStream TRSTCTL_EVENTS stream",
				MeasurementSource: "file-store byte delta after appending representative tenant lifecycle events with SyncAlways",
				Samples:           *samples, JetStreamStoreBytes: jetStream.bytesTotal,
				BytesPerUnit: jetStream.bytesPerEvent, HeadroomMultiplier: costModel.HeadroomMultiplier,
			},
			{
				ID: "audit_record_json", Unit: "tenant-facing audit record JSON", Surface: "audit projection over the event log",
				MeasurementSource: "json.Marshal(audit.Record) for a representative actor-attributed mutation",
				Samples:           1, SerializedBytes: auditRecordBytes, BytesPerUnit: auditRecordBytes,
				HeadroomMultiplier: costModel.HeadroomMultiplier,
			},
		},
		ResourceMeasurement: resources,
		CostModel:           costModel,
		Summary: perf.CapacityMeasurementSummary{
			OK:                                true,
			PostgresBytesPerManagedCredential: pg.certificateBytesPerRow + pg.credentialBytesPerRow,
			JetStreamBytesPerEvent:            jetStream.bytesPerEvent,
			Notes: []string{
				"Audit records are measured as event-log projections because trstctl does not maintain a separate audit table.",
				"Cost rows are model outputs from measured storage/resource units plus visible base/headroom assumptions; customer SKU pricing is intentionally outside this artifact.",
			},
		},
	}
	report.DerivedCapacityTiers = perf.DeriveCapacityTiers(report)

	data, err := marshal(report, *pretty)
	if err != nil {
		fail("marshal report: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail("create output dir: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fail("write %s: %v", *out, err)
	}
}

func measurePostgres(ctx context.Context, samples int) (postgresMeasurement, error) {
	dsn, cleanup, err := startEmbeddedPostgres()
	if err != nil {
		return postgresMeasurement{}, err
	}
	defer cleanup()

	s, err := store.Open(ctx, dsn)
	if err != nil {
		return postgresMeasurement{}, err
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		return postgresMeasurement{}, err
	}
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'capacity-calibration')`, tenantID); err != nil {
		return postgresMeasurement{}, err
	}
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO owners (id, tenant_id, kind, name) VALUES ($1, $2, 'Service', 'capacity owner')`, ownerID, tenantID); err != nil {
		return postgresMeasurement{}, err
	}

	var conns int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`).Scan(&conns); err != nil {
		return postgresMeasurement{}, err
	}

	certBefore, err := relationBytes(ctx, s, "certificates")
	if err != nil {
		return postgresMeasurement{}, err
	}
	if err := insertCertificates(ctx, s, samples); err != nil {
		return postgresMeasurement{}, err
	}
	certAfter, err := relationBytes(ctx, s, "certificates")
	if err != nil {
		return postgresMeasurement{}, err
	}

	credBefore, err := relationBytes(ctx, s, "credentials")
	if err != nil {
		return postgresMeasurement{}, err
	}
	if err := insertCredentials(ctx, s, samples); err != nil {
		return postgresMeasurement{}, err
	}
	credAfter, err := relationBytes(ctx, s, "credentials")
	if err != nil {
		return postgresMeasurement{}, err
	}

	return postgresMeasurement{
		certificateBytesTotal:  certAfter - certBefore,
		certificateBytesPerRow: ceilDiv(certAfter-certBefore, int64(samples)),
		credentialBytesTotal:   credAfter - credBefore,
		credentialBytesPerRow:  ceilDiv(credAfter-credBefore, int64(samples)),
		connections:            conns,
	}, nil
}

func startEmbeddedPostgres() (string, func(), error) {
	dir, err := os.MkdirTemp("", "trstctl-capacity-pg")
	if err != nil {
		return "", func() {}, err
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
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
		return "", func() {}, err
	}
	cleanup := func() {
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port), cleanup, nil
}

func relationBytes(ctx context.Context, s *store.Store, table string) (int64, error) {
	var out int64
	if err := s.SystemPool().QueryRow(ctx, `SELECT pg_total_relation_size($1::regclass)`, table).Scan(&out); err != nil {
		return 0, err
	}
	return out, nil
}

func insertCertificates(ctx context.Context, s *store.Store, samples int) error {
	batch := &pgx.Batch{}
	for i := 0; i < samples; i++ {
		id := uuidFromInt(100000 + i)
		subject := fmt.Sprintf("svc-%05d.capacity.trstctl.test", i)
		batch.Queue(
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint, key_algorithm, not_before, not_after, deployment_location, source)
			 VALUES ($1, $2, $3, $4, $5, 'capacity-ca', $6, $7, 'ECDSA-P256', now() - interval '1 day', now() + interval '90 days', 'kubernetes/ns/default', 'capacity-calibration')`,
			id, tenantID, ownerID, subject, []string{subject, "alt-" + subject}, fmt.Sprintf("%032x", i), "sha256:"+fmt.Sprintf("%064x", i),
		)
	}
	return drainBatch(ctx, s, batch, samples)
}

func insertCredentials(ctx context.Context, s *store.Store, samples int) error {
	sealed := bytes.Repeat([]byte{0x42}, 512)
	batch := &pgx.Batch{}
	for i := 0; i < samples; i++ {
		batch.Queue(
			`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
			 VALUES ($1, $2, 'issuer', $3, 'api_key', $4)`,
			uuidFromInt(200000+i), tenantID, fmt.Sprintf("issuer-%05d", i), sealed,
		)
	}
	return drainBatch(ctx, s, batch, samples)
}

func drainBatch(ctx context.Context, s *store.Store, batch *pgx.Batch, expected int) error {
	br := s.SystemPool().SendBatch(ctx, batch)
	for i := 0; i < expected; i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

func measureJetStream(ctx context.Context, samples int) (jetStreamMeasurement, error) {
	dir, err := os.MkdirTemp("", "trstctl-capacity-nats")
	if err != nil {
		return jetStreamMeasurement{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir, SyncAlways: true})
	if err != nil {
		return jetStreamMeasurement{}, err
	}
	before, err := dirSize(dir)
	if err != nil {
		_ = log.Close()
		return jetStreamMeasurement{}, err
	}
	for i := 0; i < samples; i++ {
		payload, err := representativeEventPayload(i)
		if err != nil {
			_ = log.Close()
			return jetStreamMeasurement{}, err
		}
		_, err = log.Append(ctx, events.Event{
			Type:     "certificate.issued",
			TenantID: tenantID,
			Data:     payload,
			Actor:    &events.Actor{Subject: "capacity-calibrator", Roles: []string{"admin"}},
		})
		if err != nil {
			_ = log.Close()
			return jetStreamMeasurement{}, err
		}
	}
	if err := log.Close(); err != nil {
		return jetStreamMeasurement{}, err
	}
	after, err := dirSize(dir)
	if err != nil {
		return jetStreamMeasurement{}, err
	}
	return jetStreamMeasurement{
		bytesTotal:    after - before,
		bytesPerEvent: ceilDiv(after-before, int64(samples)),
	}, nil
}

func measureAuditRecordBytes() (int64, error) {
	payload, err := representativeEventPayload(0)
	if err != nil {
		return 0, err
	}
	record := audit.Record{
		Sequence: 1, StreamSequence: 1, ID: "capacity-audit-000001", Type: "certificate.issued", TenantID: tenantID,
		Time:  time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC),
		Actor: &events.Actor{Subject: "capacity-calibrator", Roles: []string{"admin"}},
		Data:  payload,
		Hash:  "sha256:capacity-calibration-chain-head",
	}
	data, err := json.Marshal(record)
	if err != nil {
		return 0, err
	}
	return int64(len(data)), nil
}

func measureResources(path string, postgresConnections int) (perf.CapacityResourceMeasurement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return perf.CapacityResourceMeasurement{}, err
	}
	var report perf.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return perf.CapacityResourceMeasurement{}, err
	}
	if !report.Summary.OK {
		return perf.CapacityResourceMeasurement{}, fmt.Errorf("live-load artifact summary is not ok")
	}
	if err := validateServedLiveArtifact(report); err != nil {
		return perf.CapacityResourceMeasurement{}, err
	}
	out := perf.CapacityResourceMeasurement{
		LiveStackProfile:               report.StackProfile,
		PostgresCalibrationConnections: postgresConnections,
	}
	mergeResourceMetrics(&out, report.ResourceMetrics)
	for _, result := range report.Results {
		mergeResourceMetrics(&out, result.ResourceMetrics)
		if result.HotPath == "signer.rpc" && (result.Phase == "peak" || out.SignerRPCPeakThroughputPerSecond == 0) {
			if result.ResourceMetrics != nil {
				out.SignerRPCPeakMemorySysBytes = result.ResourceMetrics.MemorySysBytes
				out.SignerRPCPeakHeapInuseBytes = result.ResourceMetrics.HeapInuseBytes
			}
			out.SignerRPCPeakThroughputPerSecond = result.ThroughputPerSecond
		}
		if result.HotPath == "spine.projection_replay" && (result.Phase == "peak" || out.ProjectionReplayThroughputPerSecond == 0) {
			out.ProjectionReplayThroughputPerSecond = result.ThroughputPerSecond
		}
	}
	if out.CPUCount == 0 || out.PeakMemorySysBytes == 0 || out.SignerRPCPeakThroughputPerSecond == 0 {
		return perf.CapacityResourceMeasurement{}, fmt.Errorf("live-load artifact missing required resource counters")
	}
	return out, nil
}

func validateServedLiveArtifact(report perf.Report) error {
	if !report.ServedStack {
		return fmt.Errorf("served live-load artifact required: served_stack is false")
	}
	if report.StackProfile != requiredLiveStackProfile {
		return fmt.Errorf("served live-load artifact required: stack_profile %q, want %q", report.StackProfile, requiredLiveStackProfile)
	}
	if !hasProcessResourceMetrics(report.ResourceMetrics) {
		return fmt.Errorf("served live-load artifact missing control-plane resource counters")
	}

	requiredPhases := map[string]bool{"realistic": true, "peak": true}
	seen := make(map[string]map[string]bool, len(perf.HotPaths()))
	for _, slo := range perf.HotPaths() {
		seen[slo.HotPath] = map[string]bool{}
	}
	for _, result := range report.Results {
		phases, ok := seen[result.HotPath]
		if !ok {
			return fmt.Errorf("served live-load artifact has unknown hot path %q", result.HotPath)
		}
		if !requiredPhases[result.Phase] {
			return fmt.Errorf("served live-load artifact has unsupported phase %q for %s", result.Phase, result.HotPath)
		}
		if !result.Met {
			return fmt.Errorf("served live-load artifact has unmet result for %s/%s", result.HotPath, result.Phase)
		}
		if !result.ServedStack || result.StackProfile != report.StackProfile {
			return fmt.Errorf("served live-load artifact result %s/%s is not tied to stack profile %q", result.HotPath, result.Phase, report.StackProfile)
		}
		if !isServedRouteTransport(result.Transport) {
			return fmt.Errorf("served live-load artifact result %s/%s has non-served transport %q", result.HotPath, result.Phase, result.Transport)
		}
		if !hasProcessResourceMetrics(result.ResourceMetrics) {
			return fmt.Errorf("served live-load artifact result %s/%s missing resource counters", result.HotPath, result.Phase)
		}
		phases[result.Phase] = true
	}
	for hotPath, phases := range seen {
		for phase := range requiredPhases {
			if !phases[phase] {
				return fmt.Errorf("served live-load artifact missing %s/%s result", hotPath, phase)
			}
		}
	}
	return nil
}

func isServedRouteTransport(transport string) bool {
	if !strings.Contains(transport, "served-route:") {
		return false
	}
	lower := strings.ToLower(transport)
	for _, forbidden := range []string{"/perf/live/", "http-handler", "library-only", "synthetic", "selftest", "self-test"} {
		if strings.Contains(lower, forbidden) {
			return false
		}
	}
	return true
}

func hasProcessResourceMetrics(m *perf.ResourceMetrics) bool {
	return m != nil && m.CPUCount > 0 && m.OpenFDs > 0 && m.HeapInuseBytes > 0 && m.MemorySysBytes > 0
}

func mergeResourceMetrics(out *perf.CapacityResourceMeasurement, m *perf.ResourceMetrics) {
	if m == nil {
		return
	}
	if m.CPUCount > out.CPUCount {
		out.CPUCount = m.CPUCount
	}
	if m.OpenFDs > out.PeakOpenFDs {
		out.PeakOpenFDs = m.OpenFDs
	}
	if m.MemorySysBytes > out.PeakMemorySysBytes {
		out.PeakMemorySysBytes = m.MemorySysBytes
	}
	if m.HeapInuseBytes > out.PeakHeapInuseBytes {
		out.PeakHeapInuseBytes = m.HeapInuseBytes
	}
}

func representativeEventPayload(i int) ([]byte, error) {
	return json.Marshal(map[string]any{
		"certificate_id": uuidFromInt(300000 + i),
		"owner_id":       ownerID,
		"subject":        fmt.Sprintf("svc-%05d.capacity.trstctl.test", i),
		"sans":           []string{fmt.Sprintf("svc-%05d.capacity.trstctl.test", i), fmt.Sprintf("alt-%05d.capacity.trstctl.test", i)},
		"issuer":         "capacity-ca",
		"serial":         fmt.Sprintf("%032x", i),
		"fingerprint":    "sha256:" + fmt.Sprintf("%064x", i),
		"not_before":     "2026-06-29T00:00:00Z",
		"not_after":      "2026-09-27T00:00:00Z",
		"source":         "capacity-calibration",
	})
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func uuidFromInt(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", n)
}

func ceilDiv(n, d int64) int64 {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
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
