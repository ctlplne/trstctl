// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// A cloud_secret run with one healthy and one failing provider is partial, and
// both the run's error text and its per-provider outcomes name the provider
// that failed and why. Secret values never appear.
func TestServedPartialCloudSecretRunNamesTheFailedProvider(t *testing.T) {
	var awsSeen []string
	awsDiscovery := servedAWSSecretsManagerDouble(map[string]string{
		"demo/edge-gateway/tls": servedCloudCertPEM(t, "edge-gateway.demo.trstctl.local", "edge-gateway.demo.trstctl.local"),
	}, map[string]map[string]string{
		"demo/edge-gateway/tls": {"type": "certificate"},
	}, &awsSeen)
	t.Cleanup(awsDiscovery.Close)
	// The GCP endpoint answers every request with a permission failure, which the
	// collector does not retry.
	gcpDiscovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"status":"PERMISSION_DENIED"}}`, http.StatusForbidden)
	}))
	t.Cleanup(gcpDiscovery.Close)

	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "gcp-token")

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{
			"env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID",
			"env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY",
			"env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN",
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "discovery:read", "discovery:write", string(authz.PrivateEgress))

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "partial-cloud-secrets",
		"kind": "cloud_secret",
		"config": map[string]any{
			"providers": []map[string]any{ // #nosec G101 -- env credential references and fixture endpoints; the test needs the shape, no value is real (CWE-798)
				{"provider": "aws-secrets-manager", "region": "us-east-1", "endpoint": awsDiscovery.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, awsDiscovery.URL)}, "access_key_id_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "tag_key": "type", "tag_value": "certificate"}, // #nosec G101 -- env credential reference, not a value (CWE-798)
				{"provider": "gcp-secret-manager", "project": "acme-demo", "endpoint": gcpDiscovery.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, gcpDiscovery.URL)}, "token_ref": "env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "label_key": "type", "label_value": "certificate"},                                                                                        // #nosec G101 -- env credential reference, not a value (CWE-798)
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cloud_secret source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("start cloud discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain cloud discovery run: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get run: status %d body %s", status, body)
	}
	var run struct {
		Status        string `json:"status"`
		Targets       int    `json:"targets"`
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
		t.Fatalf("decode run: %v (%s)", err, body)
	}
	if run.Status != "partial" || run.Targets != 2 || run.Discovered != 1 || run.Failed != 1 {
		t.Fatalf("run = %+v, want a partial run with one provider discovered and one failed", run)
	}
	if !strings.Contains(run.Error, "gcp-secret-manager (") || strings.Contains(run.Error, "aws-secrets-manager") {
		t.Fatalf("run error %q should name only the failed provider", run.Error)
	}
	if len(run.TargetResults) != 2 {
		t.Fatalf("target results = %+v, want one per provider", run.TargetResults)
	}
	outcomes := map[string]string{}
	for _, result := range run.TargetResults {
		if result.Kind != "cloud_provider" {
			t.Fatalf("target result kind = %q, want cloud_provider", result.Kind)
		}
		outcomes[result.Target] = result.Status
		if result.Target == "gcp-secret-manager" && (result.Status != "failed" || result.Error == "") {
			t.Fatalf("gcp outcome = %+v, want failed with its reason", result)
		}
	}
	if outcomes["aws-secrets-manager"] != "succeeded" || outcomes["gcp-secret-manager"] != "failed" {
		t.Fatalf("outcomes = %v, want aws succeeded and gcp failed", outcomes)
	}
	if strings.Contains(string(body), "BEGIN CERTIFICATE") || strings.Contains(string(body), "SECRET") {
		t.Fatalf("run detail leaked secret material: %s", body)
	}

	findings := discoveryFindingsForRun(t, h, tok, queued.ID)
	if !strings.Contains(string(findings.Raw), "demo/edge-gateway/tls") {
		t.Fatalf("aws finding was not recorded for the partial run: %s", findings.Raw)
	}
	if strings.Contains(string(findings.Raw), "BEGIN CERTIFICATE") {
		t.Fatalf("findings carried the secret value: %s", findings.Raw)
	}
}
