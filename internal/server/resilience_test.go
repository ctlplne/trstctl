// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/observ"
)

// TestBulkheadMiddlewareShedsAndIsolates is the R2.3 acceptance "a saturation
// test on one subsystem asserts others are not starved": when a subsystem's pool
// is saturated, requests to it shed fast (503) while another subsystem's pool
// keeps serving.
func TestBulkheadMiddlewareShedsAndIsolates(t *testing.T) {
	set := bulkhead.NewSet(
		bulkhead.Config{Name: "api", Workers: 1, Queue: 0},
		bulkhead.Config{Name: "other", Workers: 1, Queue: 0},
	)
	defer set.Close()

	release := make(chan struct{})
	occupied := make(chan struct{})
	// Occupy the api pool's single worker. Retry until accepted to avoid the
	// worker-not-yet-scheduled startup race; only one task is ever accepted.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := set.Pool("api").Submit(func() { close(occupied); <-release }); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("could not occupy the api worker")
		}
		time.Sleep(time.Millisecond)
	}
	<-occupied // the api worker is now busy

	// A request through the saturated api pool is shed with 503 + Retry-After.
	apiH := bulkheadHandler(set, "api", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	apiH.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated api request = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a shed (queue-full) response should carry a Retry-After header")
	}

	// A different subsystem's pool is NOT starved by the saturated api pool.
	otherH := bulkheadHandler(set, "other", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec2 := httptest.NewRecorder()
	otherH.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec2.Code != http.StatusNoContent {
		t.Errorf("an unrelated subsystem was starved: got %d, want 204", rec2.Code)
	}

	close(release)
}

// TestBulkheadMiddlewarePassesThrough: when the pool has capacity, the request is
// served normally and the handler runs.
func TestBulkheadMiddlewarePassesThrough(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: "api", Workers: 2, Queue: 8})
	defer set.Close()
	ran := false
	h := bulkheadHandler(set, "api", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("normal request = %d, ran=%v, want 200 and the handler to run", rec.Code, ran)
	}
}

func TestMetricsEndpointSamplesBulkheadStats(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 2})
	defer set.Close()

	if err := set.Submit(bulkhead.SubsystemOutbox, func() {}); err != nil {
		t.Fatalf("submit outbox work: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if st := set.Pool(bulkhead.SubsystemOutbox).Stats(); st.Completed == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outbox work did not complete")
		}
		time.Sleep(time.Millisecond)
	}

	reg := observ.NewRegistry()
	srv := &Server{
		registry:   reg,
		bulk:       set,
		mBulkheads: observ.NewBulkheadMetrics(reg),
	}
	rec := httptest.NewRecorder()
	srv.metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`trstctl_bulkhead_workers{subsystem="outbox"} 1`,
		`trstctl_bulkhead_queue_capacity{subsystem="outbox"} 2`,
		`trstctl_bulkhead_submitted_total{subsystem="outbox"} 1`,
		`trstctl_bulkhead_completed_total{subsystem="outbox"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("/metrics missing %q from:\n%s", want, out)
		}
	}
}
