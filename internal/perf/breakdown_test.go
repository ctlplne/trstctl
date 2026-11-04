// SPDX-License-Identifier: BUSL-1.1

package perf

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// CI-L37: the breakdown leaves out each phase's warm-up request, records only
// inside a request, splits a request's time by kind with the rest as HTTP/JSON,
// and reports each field's median and the five slowest requests.
func TestIssuanceRecorderSplitsRequests(t *testing.T) {
	r := newIssuanceRecorder()
	r.add(kindPGRoundTrip, time.Second) // outside any phase: ignored
	r.startPhase("realistic")
	run := func(total time.Duration, parts map[breakdownKind]time.Duration) {
		r.begin()
		for k, d := range parts {
			r.add(k, d)
		}
		r.end(total)
	}
	run(time.Hour, map[breakdownKind]time.Duration{kindSignerRPC: time.Minute}) // the warm-up
	for i := 1; i <= 7; i++ {
		run(time.Duration(10*i)*time.Millisecond, map[breakdownKind]time.Duration{
			kindPoolAcquire: time.Millisecond, kindPGRoundTrip: time.Duration(i) * time.Millisecond,
			kindPGCommit: 2 * time.Millisecond, kindIdempotency: time.Millisecond, kindJetStreamAppend: time.Millisecond,
			kindSignerRPC: time.Millisecond,
		})
	}
	r.stopPhase()
	r.begin() // after the phase: not recorded
	r.add(kindSignerRPC, time.Minute)
	r.end(time.Hour)

	phases := r.phases()
	if len(phases) != 1 || phases[0].Phase != "realistic" || phases[0].Requests != 7 {
		t.Fatalf("phases = %+v", phases)
	}
	m := phases[0].Median
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	// Request 4 is the median: total 40 ms; 1+4+2+1+1+1 = 10 ms accounted.
	if !near(m.TotalMS, 40) || !near(m.PGRoundTripsMS, 4) || !near(m.HTTPJSONMS, 30) || !near(m.PGCommitMS, 2) || m.PGRoundTrips != 1 || m.SignerRPCs != 1 {
		t.Fatalf("median = %+v", m)
	}
	s := phases[0].Slowest
	if len(s) != 5 || !near(s[0].TotalMS, 70) || !near(s[4].TotalMS, 30) || !near(s[0].HTTPJSONMS, 70-13) {
		t.Fatalf("slowest = %+v", s)
	}
}

func TestClassifySQL(t *testing.T) {
	for sql, want := range map[string]breakdownKind{
		"commit": kindPGCommit, " COMMIT ": kindPGCommit,
		"INSERT INTO idempotency_keys (tenant_id, key) VALUES ($1, $2)": kindIdempotency,
		"select 1": kindPGRoundTrip, "BEGIN": kindPGRoundTrip,
	} {
		if got := classifySQL(sql); got != want {
			t.Errorf("classifySQL(%q) = %d, want %d", sql, got, want)
		}
	}
	// A batch that carries an idempotency statement is an idempotency round trip.
	r := newIssuanceRecorder()
	r.startPhase("peak")
	r.begin()
	tr := &breakdownTracer{rec: r}
	b := &pgx.Batch{}
	b.Queue("BEGIN")
	b.Queue("UPDATE idempotency_keys SET state = 'done'")
	ctx := tr.TraceBatchStart(context.Background(), nil, pgx.TraceBatchStartData{Batch: b})
	tr.TraceBatchEnd(ctx, nil, pgx.TraceBatchEndData{})
	ctx = tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: "commit"})
	tr.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
	if r.n[kindIdempotency] != 1 || r.n[kindPGCommit] != 1 || r.n[kindPGRoundTrip] != 0 {
		t.Fatalf("counts = %v", r.n)
	}
}

func TestTimeWriteFsync(t *testing.T) {
	d, n, err := timeWriteFsync(t.TempDir())
	if err != nil || n != 8192 || d <= 0 {
		t.Fatalf("write+fsync = %s, %d bytes, %v", d, n, err)
	}
}
