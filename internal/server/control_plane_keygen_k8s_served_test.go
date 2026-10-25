// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// Owner decision 2026-10-24: the tenant's switch governs every path that
// generates a subject key in the control plane. Kubernetes TLS auto-issuance is
// one: with the switch off a run refuses each resource before any key exists
// and says why, and with it on the run issues as before, records that the
// control plane generated each key, and keeps the custody it always recorded.
func TestServedKeygenSwitchGovernsKubernetesAutoIssuance(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read", "access:read", "access:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "k8s-keygen-switch",
		"kind": "k8s_ingress_gateway",
		"config": map[string]any{"resources": []map[string]any{{
			"kind": "Ingress", "api_version": "networking.k8s.io/v1", "namespace": "payments", "name": "web",
			"tls_secret_name": "web-tls", "hosts": []string{"switch.example.com"}, "auto_issue": true,
		}}},
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
	run := func(label string) (string, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		if status != http.StatusCreated {
			t.Fatalf("%s: start run = %d %s", label, status, body)
		}
		var queued struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" {
			t.Fatalf("%s: decode run: %v %s", label, err, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("%s: drain: %v", label, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
		if status != http.StatusOK {
			t.Fatalf("%s: read run = %d %s", label, status, body)
		}
		var done struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(body, &done); err != nil {
			t.Fatalf("%s: decode run: %v %s", label, err, body)
		}
		return done.Status, done.Error
	}
	type listedCertificate struct {
		Source    string `json:"source"`
		KeyOrigin string `json:"key_origin"`
	}
	listCertificates := func() []listedCertificate {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
		if status != http.StatusOK {
			t.Fatalf("list certificates = %d %s", status, body)
		}
		var certs struct {
			Items []listedCertificate `json:"items"`
		}
		if err := json.Unmarshal(body, &certs); err != nil {
			t.Fatalf("decode certificates: %v %s", err, body)
		}
		return certs.Items
	}
	autoIssued := func() int {
		t.Helper()
		n := 0
		for _, cert := range listCertificates() {
			if cert.Source == "discovery:k8s_ingress_gateway" {
				n++
			}
		}
		return n
	}

	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", tok, "k8s-off",
		map[string]any{"enabled": false, "reason": "clusters bring their own keys"}); status != http.StatusOK {
		t.Fatalf("turn off = %d %s", status, body)
	}
	runStatus, runError := run("switch off")
	if runStatus != "failed" || !strings.Contains(runError, "control-plane key generation is off") ||
		!strings.Contains(runError, "cert-manager") {
		t.Fatalf("auto-issuance while off = %q %q, want a failed run naming the switch and its replacement", runStatus, runError)
	}
	if n := autoIssued(); n != 0 {
		t.Fatalf("the refused run recorded %d certificates", n)
	}
	if n := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); n != 0 {
		t.Fatalf("the refused run recorded %d key generations, but generated no key", n)
	}

	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", tok, "k8s-on",
		map[string]any{"enabled": true, "reason": "the cluster has no CSR-capable issuer yet"}); status != http.StatusOK {
		t.Fatalf("turn on = %d %s", status, body)
	}
	if runStatus, runError := run("switch on"); runStatus != "succeeded" {
		t.Fatalf("auto-issuance while on = %q %q", runStatus, runError)
	}
	if n := autoIssued(); n != 1 {
		t.Fatalf("auto-issued certificates = %d, want 1", n)
	}
	for _, cert := range listCertificates() {
		if cert.Source == "discovery:k8s_ingress_gateway" && cert.KeyOrigin != "control_plane" {
			t.Fatalf("auto-issued certificate custody = %q, want control_plane", cert.KeyOrigin)
		}
	}
	if n := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); n != 1 {
		t.Fatalf("recorded key generations = %d, want 1", n)
	}
}
