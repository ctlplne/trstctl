// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/config"
)

// DP2-054: a saturated request pool is load shedding (the API answers 503 with
// Retry-After on the saturated routes), not unreadiness. /readyz must keep
// answering 200 promptly while every request-pool connection is busy: the db
// check runs on the dedicated probe pool and the datastore-reading probes treat
// pool backpressure as ready. On the starting candidate the db check pinged the
// shared pool, so one tenant's burst took the replica out of rotation.
func TestServedReadinessStaysReadyWhileTheRequestPoolIsSaturated(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	// Readiness is 200 on the idle plane first.
	if st, body := getReadyz(t, h, 8*time.Second); st != http.StatusOK {
		t.Fatalf("idle readiness: %d %s", st, body)
	}

	// Hold every connection the request pool will hand out.
	pool := h.store.SystemPool()
	var held []*pgxpool.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Release()
		}
	})
	for i := 0; i < 32; i++ {
		acquireCtx, acquireCancel := context.WithTimeout(ctx, 2*time.Second)
		c, err := pool.Acquire(acquireCtx)
		acquireCancel()
		if err != nil {
			break // the pool is exhausted: that is the condition under test
		}
		held = append(held, c)
	}
	if len(held) < 4 {
		t.Fatalf("could not saturate the request pool (held %d connections)", len(held))
	}

	// With the request pool exhausted, readiness still answers 200, promptly.
	began := time.Now()
	st, body := getReadyz(t, h, 15*time.Second)
	elapsed := time.Since(began)
	if st != http.StatusOK {
		t.Fatalf("readiness under a saturated request pool: %d after %s: %s", st, elapsed, body)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("readiness took %s under a saturated request pool; it must stay prompt", elapsed)
	}
	var view struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != "ok" || view.Checks["db"] != "ok" {
		t.Fatalf("readiness view under saturation: %+v", view)
	}
}

func getReadyz(t *testing.T, h *servedHarness, timeout time.Duration) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(h.ts.URL + "/readyz")
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
