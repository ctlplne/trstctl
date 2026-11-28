// SPDX-License-Identifier: BUSL-1.1

package observ_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/observ"
)

func TestPublicReadinessSharesAndBrieflyCachesProbeResults(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	r := observ.NewReadiness(nil, observ.Check{Name: "db", Probe: func(context.Context) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}})
	handler := r.Handler()
	request := func() {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("readiness status = %d, want 200", rec.Code)
		}
	}
	var group sync.WaitGroup
	group.Add(1)
	go func() { defer group.Done(); request() }()
	<-started
	for range 16 {
		group.Add(1)
		go func() { defer group.Done(); request() }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()
	request()
	if got := calls.Load(); got != 1 {
		t.Fatalf("public probe evaluations = %d, want one shared cached result", got)
	}
	time.Sleep(1100 * time.Millisecond)
	request()
	if got := calls.Load(); got != 2 {
		t.Fatalf("public probe evaluations after cache expiry = %d, want 2", got)
	}
}

func TestPublicReadinessReturnsOnlyDependencyVerdicts(t *testing.T) {
	r := observ.NewReadiness(nil,
		observ.Check{Name: "db", Probe: func(context.Context) error { return errors.New("postgres://private-coordinate") }},
		observ.Check{Name: "projection", Probe: func(context.Context) error { return observ.Degraded("private-probe-detail") }},
	)
	rec := httptest.NewRecorder()
	r.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want 503", rec.Code)
	}
	for _, want := range []string{`"db":"failed"`, `"projection":"degraded"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("public readiness missing %s: %s", want, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "private-") || strings.Contains(rec.Body.String(), "postgres://") {
		t.Fatalf("public readiness includes a probe detail: %s", rec.Body.String())
	}
	_, detailed, _ := r.EvaluateDetailed(context.Background())
	if detailed["db"] != "postgres://private-coordinate" || detailed["projection"] != "degraded: private-probe-detail" {
		t.Fatalf("authenticated diagnostic lost its detail: %v", detailed)
	}
}
