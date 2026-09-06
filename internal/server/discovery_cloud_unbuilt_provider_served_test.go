// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// A provider whose credential reference cannot be resolved must not take the
// whole run down with it: the healthy provider still enumerates, the run is
// partial, and the unresolved provider is named with its reason.
func TestServedCloudSecretRunWithUnresolvableProviderCredentialIsPartialAndNamed(t *testing.T) {
	var awsSeen []string
	awsDiscovery := servedAWSSecretsManagerDouble(map[string]string{
		"demo/edge-gateway/tls": servedCloudCertPEM(t, "edge-gateway.demo.trstctl.local", "edge-gateway.demo.trstctl.local"),
	}, map[string]map[string]string{
		"demo/edge-gateway/tls": {"type": "certificate"},
	}, &awsSeen)
	t.Cleanup(awsDiscovery.Close)

	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "SECRET")
	// The GCP reference is operator-approved but deliberately unset, exactly like
	// the shipped demo lab.
	t.Setenv("TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "")

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{
			"env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID",
			"env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY",
			"env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN",
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "discovery:read", "discovery:write", string(authz.PrivateEgress))

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "demo-shaped-cloud-secrets",
		"kind": "cloud_secret",
		"config": map[string]any{
			"providers": []map[string]any{ // #nosec G101 -- env credential references and fixture endpoints; the test needs the shape, no value is real (CWE-798)
				{"provider": "aws-secrets-manager", "region": "us-east-1", "endpoint": awsDiscovery.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, awsDiscovery.URL)}, "access_key_id_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "tag_key": "type", "tag_value": "certificate"}, // #nosec G101 -- env credential reference, not a value (CWE-798)
				{"provider": "gcp-secret-manager", "project": "acme-demo", "token_ref": "env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "label_key": "type", "label_value": "certificate"},                                                                                                                                                                                                                                 // #nosec G101 -- env credential reference, not a value (CWE-798)
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
			Target string `json:"target"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"target_results"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatalf("decode run: %v (%s)", err, body)
	}
	if run.Status != "partial" || run.Targets != 2 || run.Discovered != 1 || run.Failed != 1 {
		t.Fatalf("run = %+v, want partial with the AWS provider discovered and the GCP provider failed", run)
	}
	if !strings.Contains(run.Error, "gcp-secret-manager (") || !strings.Contains(run.Error, "TRSTCTL_DISCOVERY_GCP_SM_TOKEN is not set") {
		t.Fatalf("run error %q should name the unresolved provider and its credential reference", run.Error)
	}
	outcomes := map[string]string{}
	for _, result := range run.TargetResults {
		outcomes[result.Target] = result.Status
		if result.Target == "gcp-secret-manager" && !strings.Contains(result.Error, "is not set") {
			t.Fatalf("gcp outcome = %+v, want the unresolved reference named", result)
		}
	}
	if outcomes["aws-secrets-manager"] != "succeeded" || outcomes["gcp-secret-manager"] != "failed" {
		t.Fatalf("outcomes = %v, want aws succeeded and gcp failed", outcomes)
	}
	findings := discoveryFindingsForRun(t, h, tok, queued.ID)
	if !strings.Contains(string(findings.Raw), "demo/edge-gateway/tls") {
		t.Fatalf("the healthy provider's finding was not recorded: %s", findings.Raw)
	}
}
