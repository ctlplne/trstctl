// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedKubernetesCertificateSigningRequestCAPK8S04(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/certificate-signing-requests", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("kubernetes CSR support: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "BEGIN PRIVATE KEY") || strings.Contains(string(body), "bridge-signer-token") {
		t.Fatalf("kubernetes CSR support leaked credential material: %s", body)
	}

	var support struct {
		Capability           string   `json:"capability"`
		Served               bool     `json:"served"`
		APIGroup             string   `json:"api_group"`
		APIVersion           string   `json:"api_version"`
		Resource             string   `json:"resource"`
		SignerNames          []string `json:"signer_names"`
		ControllerFlow       []string `json:"controller_flow"`
		ArchitectureControls []string `json:"architecture_controls"`
		EvidenceRefs         []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(body, &support); err != nil {
		t.Fatalf("decode kubernetes CSR support: %v (%s)", err, body)
	}
	if support.Capability != "CAP-K8S-04" || !support.Served {
		t.Fatalf("kubernetes CSR support = %+v, want served CAP-K8S-04", support)
	}
	if support.APIGroup != "certificates.k8s.io" || support.APIVersion != "certificates.k8s.io/v1" || support.Resource != "certificatesigningrequests" {
		t.Fatalf("bad Kubernetes CSR resource metadata: %+v", support)
	}
	if !containsKubernetesString(support.SignerNames, "trstctl.com/trstctl") {
		t.Fatalf("signer names missing trstctl.com/trstctl: %+v", support.SignerNames)
	}
	for _, want := range []string{"internal/agent/k8s/certificate_signing_request.go", "deploy/kubernetes/rbac.yaml", "deploy/kubernetes/daemonset.yaml"} {
		if !containsKubernetesString(support.EvidenceRefs, want) {
			t.Fatalf("evidence refs missing %q: %+v", want, support.EvidenceRefs)
		}
	}
	if len(support.ControllerFlow) < 4 || !containsKubernetesString(support.ArchitectureControls, "only approved CertificateSigningRequests are signed") {
		t.Fatalf("kubernetes CSR support missing controller controls: %+v", support)
	}
}

func containsKubernetesString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
