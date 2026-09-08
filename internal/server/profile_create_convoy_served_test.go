// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/config"
)

// DP2-061: a burst of distinct profile creates must not convoy. Every create
// takes the deployment-wide projection advisory lock and runs nested
// transactions under it; on the starting candidate the waiters parked on
// request-pool connections and starved the holder's nested transactions into
// the ten-second acquire window, so a 24-way burst answered in ten-second
// steps, shed 503s and left clients timing out (cmd-0132 on g309; the
// blocker chain showed every waiter on pg_advisory_lock behind an idle holder).
func TestServedDistinctProfileCreatesDoNotConvoy(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "profile convoy tenant")
	tok := seedScopedToken(t, h.store, h.tenant, "profiles:read", "profiles:write")

	// The plane's background workers (outbox dispatchers, reconcilers, sweeps)
	// take every freed request-pool connection during a burst, so on the lab the
	// lock holder lost the race for the connection its nested transactions
	// need. Hold all but two connections here: one lock session plus one
	// nested transaction fit only if the lock session is parked elsewhere.
	const backgroundShare = 14
	held := make([]*pgxpool.Conn, 0, backgroundShare)
	defer func() {
		for _, c := range held {
			c.Release()
		}
	}()
	for i := 0; i < backgroundShare; i++ {
		acquireCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := h.store.SystemPool().Acquire(acquireCtx)
		cancel()
		if err != nil {
			t.Fatalf("hold background share of the request pool: %v", err)
		}
		held = append(held, c)
	}

	const creates = 40
	const callers = 24
	client := &http.Client{Timeout: 20 * time.Second}
	type outcome struct {
		n      int
		status int
		took   time.Duration
		err    error
		body   string
	}
	results := make(chan outcome, creates)
	jobs := make(chan int)
	var wg sync.WaitGroup
	for c := 0; c < callers; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				body, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("convoy-%d", n), "spec": map[string]any{"max_validity": "24h"}})
				req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/profiles", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Idempotency-Key", fmt.Sprintf("convoy-%d", n))
				start := time.Now()
				resp, err := client.Do(req)
				o := outcome{n: n, took: time.Since(start), err: err}
				if err == nil {
					raw, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					o.status, o.body = resp.StatusCode, string(raw)
				}
				results <- o
			}
		}()
	}
	for n := 0; n < creates; n++ {
		jobs <- n
	}
	close(jobs)
	wg.Wait()
	close(results)
	var slowest time.Duration
	created := 0
	for o := range results {
		if o.err != nil {
			t.Fatalf("create %d: %v after %s (a convoyed create ran past the client timeout)", o.n, o.err, o.took)
		}
		if o.status != http.StatusCreated {
			t.Fatalf("create %d: status %d after %s: %s", o.n, o.status, o.took, o.body)
		}
		created++
		if o.took > slowest {
			slowest = o.took
		}
	}
	if created != creates {
		t.Fatalf("created %d of %d", created, creates)
	}
	// Serialized on the projection lock is fine; parked on the request pool is
	// not: the whole burst must finish well inside one acquire window per create.
	if slowest > 8*time.Second {
		t.Fatalf("slowest distinct profile create took %s (want < 8 s): the burst convoyed on the projection lock", slowest)
	}
}
