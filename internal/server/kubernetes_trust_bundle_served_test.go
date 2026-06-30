package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedKubernetesTrustBundleDistributionCAPK8S07(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/trust-bundles", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("kubernetes trust-bundle support: status %d body %s", status, body)
	}
	upper := strings.ToUpper(string(body))
	if strings.Contains(upper, "BEGIN PRIVATE KEY") || strings.Contains(strings.ToLower(string(body)), "bridge-signer-token") || strings.Contains(strings.ToLower(string(body)), "bearer ") {
		t.Fatalf("kubernetes trust-bundle support leaked credential material: %s", body)
	}

	var support struct {
		Capability           string   `json:"capability"`
		Served               bool     `json:"served"`
		APIGroup             string   `json:"api_group"`
		APIVersion           string   `json:"api_version"`
		Resource             string   `json:"resource"`
		DistributionTargets  []string `json:"distribution_targets"`
		ControllerFlow       []string `json:"controller_flow"`
		ArchitectureControls []string `json:"architecture_controls"`
		EvidenceRefs         []string `json:"evidence_refs"`
		StatusFields         []string `json:"status_fields"`
	}
	if err := json.Unmarshal(body, &support); err != nil {
		t.Fatalf("decode kubernetes trust-bundle support: %v (%s)", err, body)
	}
	if support.Capability != "CAP-K8S-07" || !support.Served {
		t.Fatalf("kubernetes trust-bundle support = %+v, want served CAP-K8S-07", support)
	}
	if support.APIGroup != "trstctl.com" || support.APIVersion != "trstctl.com/v1alpha1" || support.Resource != "trustbundles" {
		t.Fatalf("bad Kubernetes TrustBundle resource metadata: %+v", support)
	}
	for _, want := range []string{
		"internal/agent/k8s/trust_bundle.go",
		"deploy/kubernetes/certmanager-issuer-crds.yaml",
		"deploy/kubernetes/rbac.yaml",
		"internal/agent/k8s/issuer_controller_test.go",
	} {
		if !containsKubernetesString(support.EvidenceRefs, want) {
			t.Fatalf("evidence refs missing %q: %+v", want, support.EvidenceRefs)
		}
	}
	if !containsKubernetesString(support.StatusFields, "status.bundleSHA256") {
		t.Fatalf("status fields missing bundle hash: %+v", support.StatusFields)
	}
	if len(support.DistributionTargets) == 0 || !containsKubernetesString(support.ArchitectureControls, "only public PEM CERTIFICATE blocks are accepted; private-key PEM blocks fail closed before any ConfigMap write") {
		t.Fatalf("kubernetes trust-bundle support missing target/control evidence: %+v", support)
	}
}
