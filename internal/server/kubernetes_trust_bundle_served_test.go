// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedKubernetesTrustBundleDistributionCAPK8S07(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/trust-bundles", tok, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("Kubernetes TrustBundle posture before report: status %d body %s, want 503", status, body)
	}
	seedKubernetesPosture(t, h, projections.KubernetesControllerPostureReported{
		ReportID:  "33333333-3333-3333-3333-333333333333",
		AgentID:   "44444444-4444-4444-4444-444444444444",
		ClusterID: "sha256:" + strings.Repeat("a", 64), ReconcileIntervalSeconds: 30,
		CertificateSigning: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "web-csr", UID: "csr-uid", ResourceVersion: "17", State: "ready", Reason: "signed", PublicHash: strings.Repeat("b", 64),
		}}},
		TrustBundles: projections.KubernetesPostureSection{Complete: true, Resources: []projections.KubernetesPostureResource{{
			Name: "corp-roots", UID: "bundle-uid", ResourceVersion: "9", State: "ready", Reason: "distributed", PublicHash: strings.Repeat("c", 64),
		}}},
	})

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/trust-bundles", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("Kubernetes TrustBundle posture: status %d body %s", status, body)
	}
	if strings.Contains(strings.ToUpper(string(body)), "BEGIN PRIVATE KEY") || strings.Contains(string(body), "controller_flow") || strings.Contains(string(body), "ca_bundle_pem") {
		t.Fatalf("Kubernetes TrustBundle posture leaked payload/static descriptor data: %s", body)
	}
	var got struct {
		Capability string `json:"capability"`
		Served     bool   `json:"served"`
		LastSync   string `json:"last_sync"`
		Summary    struct {
			Observed int `json:"observed"`
			Ready    int `json:"ready"`
		} `json:"summary"`
		Objects []struct {
			Name            string `json:"name"`
			UID             string `json:"uid"`
			ResourceVersion string `json:"resource_version"`
			Reason          string `json:"reason"`
			PublicHash      string `json:"public_hash"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode Kubernetes TrustBundle posture: %v (%s)", err, body)
	}
	if got.Capability != "CAP-K8S-07" || !got.Served || got.LastSync == "" || got.Summary.Observed != 1 || got.Summary.Ready != 1 {
		t.Fatalf("Kubernetes TrustBundle posture = %+v", got)
	}
	if len(got.Objects) != 1 || got.Objects[0].Name != "corp-roots" || got.Objects[0].UID != "bundle-uid" || got.Objects[0].ResourceVersion != "9" || got.Objects[0].Reason != "distributed" || len(got.Objects[0].PublicHash) != 64 {
		t.Fatalf("Kubernetes TrustBundle objects = %+v", got.Objects)
	}
}
