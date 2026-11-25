// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// CR-1015: the production tail loop first catches up, then stalls transiently:
// a PostgreSQL row lock on projection_checkpoint stands in for a slow or blocked
// tail apply, while one tenant's feed queues and delivers two batches in-band.
// After the lock is released the same tail must catch up, /readyz must recover
// and a restart must boot. At the pin the transient stall becomes permanent.
func TestCR1015AuditFeedTransientTailStallRecovers(t *testing.T) {
	r, h := newCR1015Rig(t)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.RunProjectionTail(ctx) }()
	var once sync.Once
	stopTail := func() { once.Do(func() { stop(); <-done }) }
	t.Cleanup(stopTail)
	caughtUp := func(d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			cp, _ := h.store.ProjectionCheckpoint(t.Context())
			head, _ := h.log.LastSequence(t.Context())
			if cp >= head {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	readyz := func() string {
		resp, err := http.Get(h.ts.URL + "/readyz")
		if err != nil {
			return "err:" + err.Error()
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return resp.Status + " " + strings.Join(strings.Fields(string(b)), " ")
	}
	if !caughtUp(20 * time.Second) {
		t.Fatalf("tail did not catch up before the stall: %s", r.cursor(h))
	}
	t.Logf("before the stall: %s readyz=%s", r.cursor(h), readyz())

	tx, err := h.store.SystemPool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `SELECT applied_seq FROM projection_checkpoint WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	stallStart := time.Now()
	r.batch(h)
	r.batch(h)
	t.Logf("during the stall (%s): %s", time.Since(stallStart).Round(time.Millisecond), r.cursor(h))
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	ok := caughtUp(15 * time.Second)
	t.Logf("15s after the stall cleared: caught_up=%v %s", ok, r.cursor(h))
	t.Logf("readyz after the stall cleared: %s", readyz())
	lag, _ := h.srv.tailWorker.Lag(context.Background())
	t.Logf("tail lag after the stall cleared: %d", lag)
	if !ok {
		t.Errorf("the production tail loop never caught up after a transient stall across two batches of one feed")
	} else if got := readyz(); !strings.HasPrefix(got, "200 ") {
		t.Errorf("readiness did not recover after tail catch-up: %s", got)
	}
	stopTail()
	refused := 0
	for i := 1; i <= 2; i++ {
		if _, err := r.restart(h); err != nil {
			refused++
			t.Logf("restart %d: FAILED: %v", i, err)
		} else {
			t.Logf("restart %d: ok", i)
			break
		}
	}
	if refused > 0 {
		t.Errorf("control plane refused %d boot(s) after a transient tail stall", refused)
	}
}
