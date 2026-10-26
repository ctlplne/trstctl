// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/observ"
)

type fakeAnchorWorker struct {
	interval time.Duration
	err      error
	runs     int
}

func (w *fakeAnchorWorker) RunOnce(context.Context) (editionseam.AuditAnchorSummary, error) {
	w.runs++
	return editionseam.AuditAnchorSummary{TenantsAnchored: 3, TenantsUnchanged: 1}, w.err
}

func (w *fakeAnchorWorker) Interval() time.Duration { return w.interval }

// A147: the continuous anchoring status says which of four states the
// deployment is in, the leader's pass is counted, and a failed pass is reported
// to every tenant without the cause, which names another tenant.
func TestAuditAnchoringStatusAndMetrics(t *testing.T) {
	worker := &fakeAnchorWorker{interval: 30 * time.Minute}
	srv := &Server{registry: observ.NewRegistry(), logger: slog.Default()}
	srv.anchoring = newAuditAnchoring(srv.registry, worker, true, worker.interval, "")
	if got := srv.anchoring.status(); got.State != "anchoring" || got.Cadence != 30*time.Minute || !got.LastRunAt.IsZero() {
		t.Fatalf("before a pass = %+v", got)
	}
	if sum, err := srv.RunAuditAnchoringOnce(t.Context()); err != nil || sum.TenantsAnchored != 3 || worker.runs != 1 {
		t.Fatalf("pass = %+v, %v (runs %d)", sum, err, worker.runs)
	}
	if got := srv.anchoring.status(); got.State != "anchoring" || got.LastRunAt.IsZero() {
		t.Fatalf("after a pass = %+v", got)
	}
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	worker.err = errors.New("audit anchoring: tenant " + otherTenant + ": the timestamp authority did not answer")
	if _, err := srv.RunAuditAnchoringOnce(t.Context()); err == nil {
		t.Fatal("a failed pass was hidden")
	}
	failing := srv.anchoring.status()
	if failing.State != "failing" || strings.Contains(failing.Detail, otherTenant) || failing.Detail == "" {
		t.Fatalf("failing status = %+v", failing)
	}
	recorder := httptest.NewRecorder()
	srv.registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		"trstctl_audit_anchor_runs_total 2",
		"trstctl_audit_anchors_total 6",
		"trstctl_audit_anchor_failures_total 1",
	} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("metrics omit %q", want)
		}
	}

	for name, tc := range map[string]struct {
		deps  Deps
		state string
		why   string
	}{
		"zero cadence": {Deps{AuditAnchorInterval: 0, Protocols: config.Protocols{TSA: config.ProtocolToggle{Enabled: true}}}, "off", "audit.anchor_interval is 0s"},
		"no TSA":       {Deps{AuditAnchorInterval: time.Hour}, "off", "protocols.tsa is not enabled"},
	} {
		interval, reason := auditAnchorCadence(tc.deps)
		got := newAuditAnchoring(nil, nil, true, interval, reason).status()
		if interval != 0 || got.State != tc.state || !strings.Contains(got.Detail, tc.why) {
			t.Fatalf("%s: interval %v, status %+v", name, interval, got)
		}
	}
	if interval, _ := auditAnchorCadence(Deps{AuditAnchorInterval: time.Hour, Protocols: config.Protocols{TSA: config.ProtocolToggle{Enabled: true}}}); interval != time.Hour {
		t.Fatalf("a served TSA and a cadence give interval %v", interval)
	}
	if got := newAuditAnchoring(nil, nil, false, 0, "").status(); got.State != "unlicensed" {
		t.Fatalf("core build status = %+v", got)
	}
}

// The served status route answers a core build with "unlicensed" and the
// tenant's (empty) series, and a licensed build without a served TSA with the
// reason it is off.
func TestServedAuditAnchoringStatus(t *testing.T) {
	ts, token, _ := newAuditExportHarness(t)
	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/anchors", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit/anchors = %d: %s", code, body)
	}
	var status api.AuditAnchoringStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "unlicensed" || status.AnchorCount != 0 || len(status.Anchors) != 0 || !strings.Contains(status.Verification, "--anchor-cadence") {
		t.Fatalf("core anchoring status = %+v", status)
	}
	if code, _ := doBearer(t, ts, http.MethodGet, "/api/v1/audit/anchors?limit=0", token, "", nil); code != http.StatusBadRequest {
		t.Fatalf("limit=0 = %d", code)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	var gotDeps editionseam.AuditComplianceDeps
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditAnchorInterval: time.Hour,
		AuditComplianceFactory: func(d editionseam.AuditComplianceDeps) editionseam.AuditComplianceRuntime {
			gotDeps = d
			return editionseam.AuditComplianceRuntime{}
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	if gotDeps.AnchorInterval != 0 || gotDeps.Tenants == nil {
		t.Fatalf("licensed deps without a served TSA = interval %v, tenants %v", gotDeps.AnchorInterval, gotDeps.Tenants)
	}
	if got := srv.anchoring.status(); got.State != "off" || !strings.Contains(got.Detail, "protocols.tsa") {
		t.Fatalf("licensed status without a TSA = %+v", got)
	}
}
