// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const poolTestTenant = "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"

func poolTestStore(t *testing.T) *store.Store {
	t.Helper()
	st := newStore(t)
	if err := st.UpsertTenant(context.Background(), store.Tenant{TenantID: poolTestTenant, Name: "idempotency-pool-test"}); err != nil {
		t.Fatalf("register tenant: %v", err)
	}
	return st
}

// DP2-050: a mutation's idempotency claim must not pin a pooled connection while
// the command runs, because the command opens its own transactions (emit ->
// WithTenant -> append + project). With the claim transaction held open, N
// concurrent mutations above half the pool deadlock on the pool until the
// acquire window expires and answer "datastore is busy" although the plane is
// idle; on the starting candidate eight parallel light writes took 10 s each and
// five of eight failed. The pool is 16 connections wide, so 16 concurrent
// requests whose callbacks each need one more connection reproduce it exactly.
func TestBoundMutationsDoNotHoldThePoolAcrossTheCallback(t *testing.T) {
	st := poolTestStore(t)
	idem := orchestrator.NewIdempotency(st)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	const requests = 16
	start := make(chan struct{})
	errs := make(chan error, requests)
	var wg sync.WaitGroup
	began := time.Now()
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := idem.DoBound(ctx, poolTestTenant, "pool-nesting-"+strconv.Itoa(i), "sha256:pool-nesting", func(ctx context.Context) ([]byte, error) {
				// The command's own transaction: what emit does for every event.
				err := st.WithTenant(ctx, poolTestTenant, func(tx pgx.Tx) error {
					_, execErr := tx.Exec(ctx, `SELECT pg_sleep(0.2)`)
					return execErr
				})
				if err != nil {
					return nil, err
				}
				return []byte(`{"ok":true}`), nil
			})
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	elapsed := time.Since(began)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent bound mutations must not starve each other on the pool: %v (after %s)", err, elapsed)
		}
	}
	if elapsed > 5*time.Second {
		t.Fatalf("16 concurrent 200 ms mutations took %s; the claim is still pinning the pool across the callback", elapsed)
	}
}

// AN-5 under a retry storm: identical in-flight requests (same key, same
// binding) execute the command once and every caller receives the canonical
// result, whether it arrived before or during the first execution.
func TestIdenticalInFlightBoundRequestsExecuteOnceAndReplay(t *testing.T) {
	st := poolTestStore(t)
	idem := orchestrator.NewIdempotency(st)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	const callers = 12
	var executions atomic.Int32
	start := make(chan struct{})
	results := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := idem.DoBound(ctx, poolTestTenant, "retry-storm", "sha256:retry-storm", func(ctx context.Context) ([]byte, error) {
				n := executions.Add(1)
				time.Sleep(300 * time.Millisecond)
				return []byte(`{"execution":` + string(rune('0'+n)) + `}`), nil
			})
			errs <- err
			if err == nil {
				results <- string(out)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(results)
	for err := range errs {
		if err != nil && !errors.Is(err, orchestrator.ErrInProgress) {
			t.Fatalf("identical in-flight request: %v", err)
		}
	}
	if n := executions.Load(); n != 1 {
		t.Fatalf("command executed %d times for one key, want once", n)
	}
	seen := map[string]int{}
	for r := range results {
		seen[r]++
	}
	if len(seen) != 1 {
		t.Fatalf("callers received different results for one key: %v", seen)
	}
	if seen[`{"execution":1}`] < 2 {
		t.Fatalf("waiters did not replay the canonical result: %v", seen)
	}
}
