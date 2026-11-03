// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// roundTripTracer records each statement and batch a store sends.
type roundTripTracer struct {
	mu   sync.Mutex
	sent []string
}

func (r *roundTripTracer) record(s string) {
	r.mu.Lock()
	r.sent = append(r.sent, s)
	r.mu.Unlock()
}

func (r *roundTripTracer) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

func (r *roundTripTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	r.record(d.SQL)
	return ctx
}
func (r *roundTripTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (r *roundTripTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	r.record("[batch]")
	return ctx
}
func (r *roundTripTracer) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}
func (r *roundTripTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData)     {}

// CI-L37 (d′): an idempotent command's claim and its recorded result are each
// one round trip and a COMMIT — the claim's BEGIN, tenant setup and INSERT
// travel together, and so do the record's.
func TestIdempotencyClaimAndRecordAreOneRoundTripEach(t *testing.T) {
	_ = newStore(t) // migrated, isolated tables
	tracer := &roundTripTracer{}
	s, err := store.Open(context.Background(), testDSN+"?application_name=idempotency_round_trips", store.WithQueryTracer(tracer))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	idem := orchestrator.NewIdempotency(s)
	ctx := t.Context()
	effect := func(context.Context) ([]byte, error) { return []byte("done"), nil }
	if _, err := idem.Do(ctx, tenantA, "round-trips-warm-up", effect); err != nil { // prepares the statements
		t.Fatal(err)
	}
	tracer.take()
	got, err := idem.Do(ctx, tenantA, "round-trips", effect)
	if err != nil || string(got) != "done" {
		t.Fatalf("Do = %q, %v", got, err)
	}
	sent := tracer.take()
	if len(sent) != 4 || sent[0] != "[batch]" || sent[1] != "commit" || sent[2] != "[batch]" || sent[3] != "commit" {
		t.Fatalf("a claimed, executed and recorded command sent %q; want the claim's batch, commit, the record's batch, commit", sent)
	}

	// A replay reads the recorded result and runs nothing.
	replayed, err := idem.Do(ctx, tenantA, "round-trips", func(context.Context) ([]byte, error) {
		return nil, errors.New("a replay must not run the command")
	})
	if err != nil || string(replayed) != "done" {
		t.Fatalf("replay = %q, %v", replayed, err)
	}
}

// CI-L37 (d′): concurrent duplicates of one command, sent through two stores
// as two replicas would, still run it exactly once; every caller gets its
// recorded result. PostgreSQL arbitrates the pipelined claims: one INSERT wins
// and the others wait on it, then replay.
func TestIdempotencyConcurrentDuplicatesAcrossReplicasExecuteOnce(t *testing.T) {
	_ = newStore(t)
	replicas := make([]*orchestrator.Idempotency, 2)
	for i := range replicas {
		s, err := store.Open(context.Background(), testDSN+fmt.Sprintf("?application_name=idempotency_replica_%d", i))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		replicas[i] = orchestrator.NewIdempotency(s)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	for round := 0; round < 5; round++ {
		key := fmt.Sprintf("concurrent-duplicate-%d", round)
		var runs atomic.Int32
		start := make(chan struct{})
		const callers = 16
		results := make(chan error, callers)
		for c := 0; c < callers; c++ {
			idem := replicas[c%len(replicas)]
			go func() {
				<-start
				got, err := idem.Do(ctx, tenantA, key, func(context.Context) ([]byte, error) {
					runs.Add(1)
					time.Sleep(50 * time.Millisecond) // the losers reach the claim while it is pending
					return []byte("ran-once"), nil
				})
				if err == nil && string(got) != "ran-once" {
					err = fmt.Errorf("result %q", got)
				}
				results <- err
			}()
		}
		close(start)
		for c := 0; c < callers; c++ {
			if err := <-results; err != nil {
				t.Fatalf("round %d: a duplicate caller: %v", round, err)
			}
		}
		if n := runs.Load(); n != 1 {
			t.Fatalf("round %d: %d concurrent duplicates ran the command %d times; want once", round, callers, n)
		}
	}
}
