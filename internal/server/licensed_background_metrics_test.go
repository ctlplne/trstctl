// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/observ"
)

func TestLicensedBackgroundWorkerFeatureMetrics(t *testing.T) {
	reg := observ.NewRegistry()
	worker := &telemetryWorker{name: "pcas.retirement", calls: make(chan struct{}, 1)}
	srv := &Server{
		registry:                  reg,
		featureMetrics:            observ.NewFeatureMetrics(reg),
		licensedBackgroundWorkers: []BackgroundWorker{worker},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunLicensedBackgroundWorkers(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-worker.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("licensed background worker did not run")
	}

	want := `trstctl_feature_operations_total{feature="pcas_retirement",action="worker",outcome="error"} 1`
	if out := waitForMetric(t, srv, want); !strings.Contains(out, want) {
		t.Fatalf("missing licensed worker feature metric %q\nmetrics:\n%s", want, out)
	}
}

func TestLicensedWorkerTelemetryClosedSet(t *testing.T) {
	tests := []struct {
		name    string
		feature string
		action  string
		ok      bool
	}{
		{name: "pcas.checkpoints", feature: "pcas_checkpoint", action: "worker", ok: true},
		{name: "pcas.misissuance", feature: "pcas_monitor", action: "worker", ok: true},
		{name: "pcas.retirement", feature: "pcas_retirement", action: "worker", ok: true},
		{name: "unknown", ok: false},
	}
	for _, tt := range tests {
		feature, action, ok := licensedWorkerTelemetry(tt.name)
		if feature != tt.feature || action != tt.action || ok != tt.ok {
			t.Errorf("licensedWorkerTelemetry(%q)=(%q,%q,%v), want (%q,%q,%v)",
				tt.name, feature, action, ok, tt.feature, tt.action, tt.ok)
		}
	}
}

type telemetryWorker struct {
	name  string
	calls chan struct{}
	first atomic.Bool
}

func (w *telemetryWorker) Name() string {
	return w.name
}

func (w *telemetryWorker) Run(ctx context.Context) error {
	if w.first.CompareAndSwap(false, true) {
		w.calls <- struct{}{}
		return errors.New("boom")
	}
	<-ctx.Done()
	return ctx.Err()
}

func waitForMetric(t *testing.T, srv *Server, want string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		srv.metricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		out = rec.Body.String()
		if strings.Contains(out, want) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	return out
}
