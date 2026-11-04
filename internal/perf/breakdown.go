// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The issuance breakdown (CI-L37, owner note 2026-11-04): measurement only, from
// timestamps alone — no profiler runs during the gate, no threshold reads it,
// and nothing here changes what passes. For every measured api.issuance
// request in each live phase it records where the request's time went: waiting
// for a pooled PostgreSQL connection, PostgreSQL statements and batches (each a
// round trip), commits, the idempotency claim and completion statements, event
// appends to JetStream, and signer RPCs (the signer's journal fsyncs are inside
// them); what is left of the request's wall time is HTTP, JSON and handler
// work. PostgreSQL's wait events are sampled while each phase's issuances run,
// and one write+fsync times the work disk.

type breakdownKind int

const (
	kindPoolAcquire breakdownKind = iota
	kindPGRoundTrip
	kindPGCommit
	kindIdempotency
	kindJetStreamAppend
	kindSignerRPC
	numBreakdownKinds
)

// IssuanceRequest is one measured issuance's time, split by where it went.
type IssuanceRequest struct {
	TotalMS           float64 `json:"total_ms"`
	PoolAcquireMS     float64 `json:"pool_acquire_ms"`
	PGRoundTripsMS    float64 `json:"pg_round_trips_ms"`
	PGCommitMS        float64 `json:"pg_commit_ms"`
	IdempotencyMS     float64 `json:"idempotency_ms"`
	JetStreamAppendMS float64 `json:"jetstream_append_ms"`
	SignerRPCMS       float64 `json:"signer_rpc_ms"`
	// HTTPJSONMS is the rest of the wall time: HTTP, JSON and handler work.
	HTTPJSONMS            float64 `json:"http_json_ms"`
	PoolAcquires          int     `json:"pool_acquires"`
	PGRoundTrips          int     `json:"pg_round_trips"`
	PGCommits             int     `json:"pg_commits"`
	IdempotencyStatements int     `json:"idempotency_statements"`
	JetStreamAppends      int     `json:"jetstream_appends"`
	SignerRPCs            int     `json:"signer_rpcs"`
}

// WaitEventSample counts the PostgreSQL wait events active client backends
// showed, sampled while a phase's issuances ran ("CPU:running" is a backend
// that was active and waiting on nothing).
type WaitEventSample struct {
	IntervalMS int            `json:"interval_ms"`
	Samples    int            `json:"samples"`
	Counts     map[string]int `json:"counts"`
	Error      string         `json:"error,omitempty"`
}

// IssuancePhaseBreakdown is one load phase's issuance breakdown: each field's
// own median (so the medians need not add up to the median total) and the five
// slowest requests whole.
type IssuancePhaseBreakdown struct {
	Phase      string            `json:"phase"`
	Requests   int               `json:"requests"`
	Median     IssuanceRequest   `json:"median"`
	Slowest    []IssuanceRequest `json:"slowest"`
	WaitEvents WaitEventSample   `json:"postgres_wait_events"`
}

// IssuanceBreakdown is the perf-live artifact's account of where api.issuance
// spends its time.
type IssuanceBreakdown struct {
	Method           string                   `json:"method"`
	DiskWriteFsyncMS float64                  `json:"disk_write_fsync_ms"`
	DiskWriteBytes   int                      `json:"disk_write_bytes"`
	DiskError        string                   `json:"disk_error,omitempty"`
	Phases           []IssuancePhaseBreakdown `json:"phases"`
}

const breakdownMethod = "Timestamps only, recorded while one issuance runs at a time: pgx's tracer times pool acquires, " +
	"statements and batches (a batch is one round trip; a statement or batch that touches the idempotency table counts as " +
	"idempotency; a lone COMMIT as commit), the event log times each append, and the signer client times each RPC. " +
	"http_json_ms is the rest of the request's wall time. Statements other goroutines send during a request are counted in it. " +
	"The first request of each phase warms the path and is left out, as the gate leaves it out."

// issuanceRecorder gathers one request's timings at a time.
type issuanceRecorder struct {
	mu      sync.Mutex
	phase   string
	warm    bool
	inReq   bool
	d       [numBreakdownKinds]time.Duration
	n       [numBreakdownKinds]int
	byPhase map[string][]IssuanceRequest
	order   []string
}

func newIssuanceRecorder() *issuanceRecorder {
	return &issuanceRecorder{byPhase: map[string][]IssuanceRequest{}}
}

// startPhase records the next requests under phase; the first one is the
// gate's warm-up and is left out.
func (r *issuanceRecorder) startPhase(phase string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phase, r.warm = phase, true
	if _, ok := r.byPhase[phase]; !ok {
		r.order = append(r.order, phase)
		r.byPhase[phase] = nil
	}
}

func (r *issuanceRecorder) stopPhase() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phase = ""
}

func (r *issuanceRecorder) begin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase == "" {
		return
	}
	r.inReq = true
	r.d, r.n = [numBreakdownKinds]time.Duration{}, [numBreakdownKinds]int{}
}

func (r *issuanceRecorder) add(kind breakdownKind, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.inReq {
		return
	}
	r.d[kind] += d
	r.n[kind]++
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

func (r *issuanceRecorder) end(total time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.inReq {
		return
	}
	r.inReq = false
	if r.warm {
		r.warm = false
		return
	}
	req := IssuanceRequest{
		TotalMS: ms(total), PoolAcquireMS: ms(r.d[kindPoolAcquire]), PGRoundTripsMS: ms(r.d[kindPGRoundTrip]),
		PGCommitMS: ms(r.d[kindPGCommit]), IdempotencyMS: ms(r.d[kindIdempotency]),
		JetStreamAppendMS: ms(r.d[kindJetStreamAppend]), SignerRPCMS: ms(r.d[kindSignerRPC]),
		PoolAcquires: r.n[kindPoolAcquire], PGRoundTrips: r.n[kindPGRoundTrip], PGCommits: r.n[kindPGCommit],
		IdempotencyStatements: r.n[kindIdempotency], JetStreamAppends: r.n[kindJetStreamAppend], SignerRPCs: r.n[kindSignerRPC],
	}
	var accounted time.Duration
	for _, d := range r.d {
		accounted += d
	}
	if rest := total - accounted; rest > 0 {
		req.HTTPJSONMS = ms(rest)
	}
	r.byPhase[r.phase] = append(r.byPhase[r.phase], req)
}

// phases summarizes every phase recorded, in the order they ran.
func (r *issuanceRecorder) phases() []IssuancePhaseBreakdown {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]IssuancePhaseBreakdown, 0, len(r.order))
	for _, phase := range r.order {
		reqs := append([]IssuanceRequest(nil), r.byPhase[phase]...)
		out = append(out, IssuancePhaseBreakdown{Phase: phase, Requests: len(reqs), Median: medianRequest(reqs), Slowest: slowest(reqs, 5)})
	}
	return out
}

func medianOf(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	if len(values)%2 == 1 {
		return values[len(values)/2]
	}
	return (values[len(values)/2-1] + values[len(values)/2]) / 2
}

func medianInt(values []int) int {
	f := make([]float64, len(values))
	for i, v := range values {
		f[i] = float64(v)
	}
	return int(medianOf(f) + 0.5)
}

// medianRequest is each field's own median.
func medianRequest(reqs []IssuanceRequest) IssuanceRequest {
	pick := func(get func(IssuanceRequest) float64) float64 {
		values := make([]float64, len(reqs))
		for i, r := range reqs {
			values[i] = get(r)
		}
		return medianOf(values)
	}
	count := func(get func(IssuanceRequest) int) int {
		values := make([]int, len(reqs))
		for i, r := range reqs {
			values[i] = get(r)
		}
		return medianInt(values)
	}
	return IssuanceRequest{
		TotalMS:               pick(func(r IssuanceRequest) float64 { return r.TotalMS }),
		PoolAcquireMS:         pick(func(r IssuanceRequest) float64 { return r.PoolAcquireMS }),
		PGRoundTripsMS:        pick(func(r IssuanceRequest) float64 { return r.PGRoundTripsMS }),
		PGCommitMS:            pick(func(r IssuanceRequest) float64 { return r.PGCommitMS }),
		IdempotencyMS:         pick(func(r IssuanceRequest) float64 { return r.IdempotencyMS }),
		JetStreamAppendMS:     pick(func(r IssuanceRequest) float64 { return r.JetStreamAppendMS }),
		SignerRPCMS:           pick(func(r IssuanceRequest) float64 { return r.SignerRPCMS }),
		HTTPJSONMS:            pick(func(r IssuanceRequest) float64 { return r.HTTPJSONMS }),
		PoolAcquires:          count(func(r IssuanceRequest) int { return r.PoolAcquires }),
		PGRoundTrips:          count(func(r IssuanceRequest) int { return r.PGRoundTrips }),
		PGCommits:             count(func(r IssuanceRequest) int { return r.PGCommits }),
		IdempotencyStatements: count(func(r IssuanceRequest) int { return r.IdempotencyStatements }),
		JetStreamAppends:      count(func(r IssuanceRequest) int { return r.JetStreamAppends }),
		SignerRPCs:            count(func(r IssuanceRequest) int { return r.SignerRPCs }),
	}
}

// slowest is the n slowest requests by wall time, slowest first.
func slowest(reqs []IssuanceRequest, n int) []IssuanceRequest {
	sorted := append([]IssuanceRequest(nil), reqs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TotalMS > sorted[j].TotalMS })
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// breakdownTracer is the store's pgx tracer during the live gate.
type breakdownTracer struct{ rec *issuanceRecorder }

type tracedStart struct {
	at   time.Time
	kind breakdownKind
}

type (
	queryTraceKey   struct{}
	batchTraceKey   struct{}
	acquireTraceKey struct{}
)

func classifySQL(sql string) breakdownKind {
	s := strings.ToLower(strings.TrimSpace(sql))
	switch {
	case s == "commit":
		return kindPGCommit
	case strings.Contains(s, "idempotency"):
		return kindIdempotency
	}
	return kindPGRoundTrip
}

func (t *breakdownTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, queryTraceKey{}, tracedStart{at: time.Now(), kind: classifySQL(data.SQL)})
}

func (t *breakdownTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if s, ok := ctx.Value(queryTraceKey{}).(tracedStart); ok {
		t.rec.add(s.kind, time.Since(s.at))
	}
}

func (t *breakdownTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	kind := kindPGRoundTrip
	if data.Batch != nil {
		for _, q := range data.Batch.QueuedQueries {
			if classifySQL(q.SQL) == kindIdempotency {
				kind = kindIdempotency
				break
			}
		}
	}
	return context.WithValue(ctx, batchTraceKey{}, tracedStart{at: time.Now(), kind: kind})
}

func (t *breakdownTracer) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}

func (t *breakdownTracer) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchEndData) {
	if s, ok := ctx.Value(batchTraceKey{}).(tracedStart); ok {
		t.rec.add(s.kind, time.Since(s.at))
	}
}

func (t *breakdownTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, acquireTraceKey{}, time.Now())
}

func (t *breakdownTracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireEndData) {
	if at, ok := ctx.Value(acquireTraceKey{}).(time.Time); ok {
		t.rec.add(kindPoolAcquire, time.Since(at))
	}
}

// waitEventSampler samples pg_stat_activity on its own connection — untraced,
// outside every pool — while a phase's issuances run.
type waitEventSampler struct {
	stop chan struct{}
	done chan WaitEventSample
}

const waitEventQuery = `SELECT coalesce(wait_event_type, 'CPU'), coalesce(wait_event, 'running')
FROM pg_stat_activity WHERE state = 'active' AND backend_type = 'client backend' AND pid <> pg_backend_pid()`

func startWaitEventSampler(ctx context.Context, base *pgx.ConnConfig, interval time.Duration) *waitEventSampler {
	s := &waitEventSampler{stop: make(chan struct{}), done: make(chan WaitEventSample, 1)}
	go func() {
		out := WaitEventSample{IntervalMS: int(interval / time.Millisecond), Counts: map[string]int{}}
		defer func() { s.done <- out }()
		cfg := base.Copy()
		cfg.Tracer = nil
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			out.Error = err.Error()
			return
		}
		defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			rows, err := conn.Query(ctx, waitEventQuery)
			if err != nil {
				out.Error = err.Error()
				return
			}
			for rows.Next() {
				var kind, event string
				if err := rows.Scan(&kind, &event); err == nil {
					out.Counts[kind+":"+event]++
				}
			}
			rows.Close()
			out.Samples++
		}
	}()
	return s
}

func (s *waitEventSampler) finish() WaitEventSample {
	close(s.stop)
	return <-s.done
}

// timeWriteFsync writes one PostgreSQL page to a new file in dir and fsyncs it.
func timeWriteFsync(dir string) (time.Duration, int, error) {
	f, err := os.CreateTemp(dir, "fsync-probe-*")
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	page := make([]byte, 8192)
	start := time.Now()
	if _, err := f.Write(page); err != nil {
		return 0, 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, 0, fmt.Errorf("fsync: %w", err)
	}
	return time.Since(start), len(page), nil
}
