// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestKubernetesPostureBuildsCountsLastSyncAndPerObjectState(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	rows := []store.KubernetesControllerPosture{
		{
			ControllerID: "11111111-1111-1111-1111-111111111111", ClusterID: "sha256:" + strings.Repeat("a", 64),
			ReportID: "33333333-3333-3333-3333-333333333333", ReconcileComplete: true,
			ReconcileIntervalSeconds: 30, ReportedAt: now.Add(-20 * time.Second),
			Resources: []store.KubernetesPostureResource{
				{Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64)},
				{Name: "db-csr", UID: "db-uid", ResourceVersion: "19", State: "pending", Reason: "approval_pending", PublicHash: strings.Repeat("c", 64)},
			},
		},
		{
			ControllerID: "22222222-2222-2222-2222-222222222222", ClusterID: "sha256:" + strings.Repeat("d", 64),
			ReportID: "44444444-4444-4444-4444-444444444444", ReconcileComplete: false, FailureCode: "reconcile_failed",
			ReconcileIntervalSeconds: 30, ReportedAt: now.Add(-2 * time.Minute),
			Resources: []store.KubernetesPostureResource{{Name: "broken-csr", UID: "broken-uid", ResourceVersion: "4", State: "failed", Reason: "controller_error"}},
		},
	}
	state := buildKubernetesPosture(rows, now)
	if !state.served || state.lastSync != now.Add(-20*time.Second).Format(time.RFC3339) {
		t.Fatalf("served/last sync = %v/%q", state.served, state.lastSync)
	}
	if state.summary != (KubernetesPostureSummary{Controllers: 2, Complete: 1, Stale: 1, Observed: 3, Ready: 1, Pending: 1, Failed: 1}) {
		t.Fatalf("summary = %+v", state.summary)
	}
	if len(state.controllers) != 2 || state.controllers[0].Stale || !state.controllers[1].Stale || len(state.objects) != 3 {
		t.Fatalf("controllers/objects = %+v / %+v", state.controllers, state.objects)
	}
	if state.objects[0].ResourceVersion != "17" || state.objects[0].PublicHash != strings.Repeat("b", 64) {
		t.Fatalf("object metadata = %+v", state.objects[0])
	}
}

func TestKubernetesPostureRoutesFailHonestlyWithoutControllerReport(t *testing.T) {
	handler := New(nil, nil, nil, WithInsecureHeaderResolver())
	for _, path := range []string{
		"/api/v1/kubernetes/certificate-signing-requests",
		"/api/v1/kubernetes/trust-bundles",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
		req.Header.Set("X-Roles", "admin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status = %d body=%s, want 503 before an authenticated report", path, rec.Code, rec.Body.String())
		}
		body := strings.ToLower(rec.Body.String())
		if strings.Contains(body, `"served":true`) || strings.Contains(body, "controller_flow") {
			t.Fatalf("%s returned static served descriptor: %s", path, rec.Body.String())
		}
	}
}
