package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
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
