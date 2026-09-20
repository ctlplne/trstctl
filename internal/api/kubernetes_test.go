// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

type fakeKubernetesPostureReader struct {
	rows  map[string][]store.KubernetesControllerPosture
	calls []string
}

func (f *fakeKubernetesPostureReader) ListKubernetesControllerPosture(_ context.Context, tenantID, capability string) ([]store.KubernetesControllerPosture, error) {
	f.calls = append(f.calls, tenantID+"/"+capability)
	return append([]store.KubernetesControllerPosture(nil), f.rows[capability]...), nil
}

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

func TestKubernetesPostureRoutesRequireAndUseExplicitProductionReaders(t *testing.T) {
	now := time.Now().UTC()
	csr := &fakeKubernetesPostureReader{rows: map[string][]store.KubernetesControllerPosture{
		store.KubernetesPostureCertificateSigningRequests: {{
			ControllerID: "11111111-1111-1111-1111-111111111111", ClusterID: "sha256:" + strings.Repeat("a", 64),
			ReportID: "33333333-3333-3333-3333-333333333333", ReconcileComplete: true,
			ReconcileIntervalSeconds: 30, ReportedAt: now,
			Resources: []store.KubernetesPostureResource{{Name: "real-csr", UID: "csr-uid", ResourceVersion: "7", State: "ready", Reason: "signed"}},
		}},
	}}
	trust := &fakeKubernetesPostureReader{rows: map[string][]store.KubernetesControllerPosture{
		store.KubernetesPostureTrustBundles: {{
			ControllerID: "11111111-1111-1111-1111-111111111111", ClusterID: "sha256:" + strings.Repeat("a", 64),
			ReportID: "44444444-4444-4444-4444-444444444444", ReconcileComplete: true,
			ReconcileIntervalSeconds: 30, ReportedAt: now,
			Resources: []store.KubernetesPostureResource{{Name: "real-bundle", UID: "bundle-uid", ResourceVersion: "8", State: "ready", Reason: "distributed"}},
		}},
	}}
	handler := New(nil, nil, nil,
		WithInsecureHeaderResolver(),
		WithKubernetesCSRPosture(csr),
		WithKubernetesTrustBundlePosture(trust),
	)
	for _, tc := range []struct {
		path, object string
	}{
		{path: "/api/v1/kubernetes/certificate-signing-requests", object: "real-csr"},
		{path: "/api/v1/kubernetes/trust-bundles", object: "real-bundle"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("X-Tenant-ID", "99999999-9999-4999-8999-999999999999")
		req.Header.Set("X-Roles", "admin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"`+tc.object+`"`) {
			t.Fatalf("%s status=%d body=%s, want explicit projected object %s", tc.path, rec.Code, rec.Body.String(), tc.object)
		}
	}
	if len(csr.calls) != 1 || !strings.HasSuffix(csr.calls[0], "/"+store.KubernetesPostureCertificateSigningRequests) {
		t.Fatalf("CSR reader calls=%v", csr.calls)
	}
	if len(trust.calls) != 1 || !strings.HasSuffix(trust.calls[0], "/"+store.KubernetesPostureTrustBundles) {
		t.Fatalf("TrustBundle reader calls=%v", trust.calls)
	}
}

// TestKubernetesNarrativeFieldsArePopulatedAndDerived is the AUD-8 regression:
// the six narrative arrays were hardcoded empty literals with no code path that
// could populate them, so the console rendered "zero distribution targets, zero
// architecture controls" as posture. The static sets must describe the shipped
// controller (non-empty), and recommended_next_actions must DERIVE from the
// posture rows: non-empty for a degraded estate, empty for a healthy one.
func TestKubernetesNarrativeFieldsArePopulatedAndDerived(t *testing.T) {
	now := time.Now().UTC()
	healthy := store.KubernetesControllerPosture{
		ControllerID: "11111111-1111-1111-1111-111111111111", ClusterID: "sha256:" + strings.Repeat("a", 64),
		ReportID: "33333333-3333-3333-3333-333333333333", ReconcileComplete: true,
		ReconcileIntervalSeconds: 30, ReportedAt: now,
		Resources: []store.KubernetesPostureResource{{Name: "ok", UID: "u1", ResourceVersion: "1", State: "ready", Reason: "signed"}},
	}
	degraded := store.KubernetesControllerPosture{
		ControllerID: "22222222-2222-2222-2222-222222222222", ClusterID: "sha256:" + strings.Repeat("d", 64),
		ReportID: "44444444-4444-4444-4444-444444444444", ReconcileComplete: false, FailureCode: "reconcile_failed",
		ReconcileIntervalSeconds: 30, ReportedAt: now.Add(-10 * time.Minute),
		Resources: []store.KubernetesPostureResource{{Name: "broken", UID: "u2", ResourceVersion: "2", State: "failed", Reason: "controller_error"}},
	}

	serve := func(rows []store.KubernetesControllerPosture, path, capability string) map[string]any {
		t.Helper()
		reader := &fakeKubernetesPostureReader{rows: map[string][]store.KubernetesControllerPosture{capability: rows}}
		handler := New(nil, nil, nil, WithInsecureHeaderResolver(),
			WithKubernetesCSRPosture(reader), WithKubernetesTrustBundlePosture(reader))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Tenant-ID", "99999999-9999-4999-8999-999999999999")
		req.Header.Set("X-Roles", "admin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return out
	}
	arrayLen := func(out map[string]any, field string) int {
		v, ok := out[field].([]any)
		if !ok {
			t.Fatalf("field %q missing or not an array: %v", field, out[field])
		}
		return len(v)
	}

	// Trust bundles, degraded estate: every narrative field populated, actions derived.
	tb := serve([]store.KubernetesControllerPosture{healthy, degraded},
		"/api/v1/kubernetes/trust-bundles", store.KubernetesPostureTrustBundles)
	for _, field := range []string{"distribution_targets", "controller_flow", "architecture_controls", "evidence_refs", "residuals"} {
		if arrayLen(tb, field) == 0 {
			t.Fatalf("trust-bundles %q is empty — the console reads that as \"this control plane does nothing\" (AUD-8)", field)
		}
	}
	if arrayLen(tb, "recommended_next_actions") == 0 {
		t.Fatal("degraded estate produced zero recommended_next_actions; the field must derive from posture")
	}

	// CSR support, healthy estate: static narrative populated, zero actions.
	csr := serve([]store.KubernetesControllerPosture{healthy},
		"/api/v1/kubernetes/certificate-signing-requests", store.KubernetesPostureCertificateSigningRequests)
	for _, field := range []string{"controller_flow", "architecture_controls", "evidence_refs", "residuals"} {
		if arrayLen(csr, field) == 0 {
			t.Fatalf("certificate-signing-requests %q is empty (AUD-8)", field)
		}
	}
	if got := arrayLen(csr, "recommended_next_actions"); got != 0 {
		t.Fatalf("healthy estate produced %d recommended actions, want 0 (empty now truthfully means \"nothing to do\")", got)
	}
}
