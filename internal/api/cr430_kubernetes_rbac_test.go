// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestCR430TrustBundleDescriptorStatesConfigMapNamespaceScope(t *testing.T) {
	reader := &fakeKubernetesPostureReader{rows: map[string][]store.KubernetesControllerPosture{
		store.KubernetesPostureTrustBundles: {{
			ControllerID: "11111111-1111-1111-1111-111111111111", ClusterID: "fixture-cluster",
			ReportID: "22222222-2222-2222-2222-222222222222", ReconcileComplete: true,
			ReconcileIntervalSeconds: 30, ReportedAt: time.Now().UTC(),
		}},
	}}
	handler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithKubernetesTrustBundlePosture(reader))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kubernetes/trust-bundles", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust-bundle descriptor status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		RBACRules []struct {
			Resource string `json:"resource"`
			Scope    string `json:"scope"`
		} `json:"rbac_rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, rule := range payload.RBACRules {
		if rule.Resource == "configmaps" {
			if rule.Scope != "namespaced" {
				t.Fatalf("CAP-K8S-07 advertises ConfigMap scope %q, want namespaced", rule.Scope)
			}
			return
		}
	}
	t.Fatal("CAP-K8S-07 omitted its ConfigMap distribution RBAC rule")
}
