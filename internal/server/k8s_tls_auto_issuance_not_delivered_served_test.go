// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Owner decision 2026-10-25 (B15-L1): Kubernetes Ingress and Gateway TLS is
// delivered the cert-manager way. The in-cluster agent generates the key inside
// the cluster, sends a CSR and writes the TLS Secret itself with a signed
// receipt; the control plane never generates the key. Until that agent mode
// exists a run must not report an auto-issued certificate as issued or served:
// it records each resource it discovered and reports it not delivered with the
// reason, generating no key and recording no certificate, whether the tenant's
// key-generation switch is on or off.
func TestServedKubernetesTLSAutoIssuanceIsReportedNotDelivered(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read", "access:read", "access:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "k8s-not-delivered",
		"kind": "k8s_ingress_gateway",
		"config": map[string]any{"resources": []map[string]any{
			{"kind": "Ingress", "api_version": "networking.k8s.io/v1", "namespace": "payments", "name": "web",
				"tls_secret_name": "web-tls", "hosts": []string{"web.example.com"}, "auto_issue": true},
			{"kind": "Gateway", "namespace": "edge", "name": "gw",
				"tls_secret_name": "gw-tls", "hosts": []string{"gw.example.com"}, "auto_issue": true},
		}},
	})
	if status != http.StatusCreated {
		t.Fatalf("create source = %d %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
		t.Fatalf("decode source: %v %s", err, body)
	}

	for _, enabled := range []bool{true, false} {
		if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", tok, "k8s-switch-"+map[bool]string{true: "on", false: "off"}[enabled],
			map[string]any{"enabled": enabled, "reason": "B15-L1 interim check"}); status != http.StatusOK {
			t.Fatalf("set switch %v = %d %s", enabled, status, body)
		}
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		if status != http.StatusCreated {
			t.Fatalf("start run = %d %s", status, body)
		}
		var queued struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" {
			t.Fatalf("decode run: %v %s", err, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain: %v", err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("read run = %d %s", status, body)
		}
		var run struct {
			Status        string `json:"status"`
			Discovered    int    `json:"discovered"`
			Failed        int    `json:"failed"`
			Error         string `json:"error"`
			TargetResults []struct {
				Kind   string `json:"kind"`
				Target string `json:"target"`
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"target_results"`
		}
		if err := json.Unmarshal(body, &run); err != nil {
			t.Fatalf("decode run: %v %s", err, body)
		}
		if run.Status != "partial" || run.Discovered != 2 || run.Failed != 0 ||
			!strings.Contains(run.Error, "2 Kubernetes TLS resources were not delivered") || !strings.Contains(run.Error, "in-cluster agent") {
			t.Fatalf("switch %v: run = %+v, want partial naming both resources as not delivered and why", enabled, run)
		}
		outcomes := map[string]string{}
		for _, result := range run.TargetResults {
			if result.Kind != "k8s_tls_auto_issuance" || result.Error == "" {
				t.Fatalf("switch %v: target result %+v, want a Kubernetes TLS outcome with its reason", enabled, result)
			}
			// The status already says not delivered; the reason does not repeat it,
			// so the console can show it once beside the status.
			if strings.HasPrefix(result.Error, "not delivered") || !strings.Contains(result.Error, "in-cluster agent") {
				t.Fatalf("switch %v: target result reason %q, want the reason alone", enabled, result.Error)
			}
			outcomes[result.Target] = result.Status
		}
		if outcomes["Ingress:payments/web"] != "not_delivered" || outcomes["Gateway:edge/gw"] != "not_delivered" {
			t.Fatalf("switch %v: outcomes = %v, want both resources not delivered", enabled, outcomes)
		}
		if findings := discoveryFindingsForRun(t, h, tok, queued.ID); !strings.Contains(string(findings.Raw), "web-tls") || !strings.Contains(string(findings.Raw), "gw-tls") {
			t.Fatalf("switch %v: the discovered resources were not recorded: %s", enabled, findings.Raw)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates = %d %s", status, body)
	}
	if strings.Contains(string(body), "discovery:k8s_ingress_gateway") {
		t.Fatalf("a run recorded an auto-issued certificate: %s", body)
	}
	if n := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); n != 0 {
		t.Fatalf("the control plane recorded %d key generations for Kubernetes TLS", n)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/tenant/key-generation", tok, nil)
	var readout struct {
		Paths    []string `json:"paths"`
		Guidance string   `json:"guidance"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &readout) != nil || len(readout.Paths) != 4 ||
		strings.Contains(strings.Join(readout.Paths, "\n"), "Kubernetes") || !strings.Contains(readout.Guidance, "not delivered") {
		t.Fatalf("the key-generation readout = %d %s, want four governed paths without Kubernetes auto-issuance", status, body)
	}
}
