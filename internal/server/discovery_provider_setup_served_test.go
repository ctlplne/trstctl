// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/weakkey"
)

// CR-405: the run and target should retain fixed local setup instructions.
func TestServedDiscoveryReportsMissingProviderSetup(t *testing.T) {
	const knownEnv = "TRSTCTL_FIXTURE_PROVIDER_SETUP_TOKEN"
	const missingEnv = "fixture_handshake_provider_token"
	const ref = "env:" + knownEnv
	const missingRef = "env:" + missingEnv
	t.Setenv(knownEnv, "fixture-provider-credential")
	t.Setenv(missingEnv, "")
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(endpoint.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		bindOutboundEnvCredentialRefs("cloud_secret", []string{endpoint.URL}, ref, missingRef),
		bindOutboundEnvCredentialRefs("secret_store", []string{endpoint.URL}, ref))
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))
	for _, tc := range []struct {
		name, provider, kind, guidance string
		fields                         map[string]any
	}{
		{"gcp-project", "gcp-secret-manager", "cloud_secret", "gcp-secret-manager project is required", map[string]any{"token_ref": ref}},
		{"gcp-reference", "gcp-secret-manager", "cloud_secret", "token_ref is required", map[string]any{"project": "fixture-project"}},
		{"bound-unset-name", "gcp-secret-manager", "cloud_secret", "env credential reference " + missingEnv + " is not set", map[string]any{"project": "fixture-project", "token_ref": missingRef}},
		{"conjur-account", "conjur", "secret_store", "conjur: account, login and api_key_ref are required", map[string]any{"api_key_ref": ref}},
		{"doppler-project", "doppler", "secret_store", "doppler: configs belong to a project; set project", map[string]any{"token_ref": ref, "configs": []string{"fixture-config"}}},
		{"compute-reference", "gcp-compute", "cloud_network_path", "provider 1: token_ref is required", map[string]any{"project": "fixture-project"}},
		{"compute-project", "gcp-compute", "cloud_network_path", "provider 1: gcp-compute project is required", map[string]any{}},
		{"ec2-region", "aws-ec2", "cloud_network_path", "provider 1: aws-ec2 region is required", map[string]any{}},
		{"azure-subscription", "azure-network", "cloud_network_path", "provider 1: azure-network subscription_id is required", map[string]any{}},
		{"iam-reference", "aws-iam", "cloud_access_key", "provider 1: access_key_id_ref is required", map[string]any{}},
		{"kms-region", "aws-kms", "cloud_kms_key", "provider 1: aws-kms requires a region", map[string]any{}},
		{"elbv2-region", "aws-elbv2", "load_balancer_tls", "provider 1: aws-elbv2 requires a region", map[string]any{}},
		{"bigip-username", "f5-bigip", "load_balancer_tls", "provider 1: username_ref is required", map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			create := func(path string, payload any) string {
				t.Helper()
				status, raw := secretsReq(t, h, http.MethodPost, path, token, payload)
				var response struct {
					ID string `json:"id"`
				}
				if status != http.StatusCreated || json.Unmarshal(raw, &response) != nil || response.ID == "" {
					t.Fatalf("create %s returned %d or omitted the identity", path, status)
				}
				return response.ID
			}
			tc.fields["provider"], tc.fields["endpoint"] = tc.provider, endpoint.URL
			tc.fields["allow_private_endpoint"] = true
			tc.fields["private_egress_cidrs"] = []string{serviceNowSinkCIDR(t, endpoint.URL)}
			sourceID := create("/api/v1/discovery/sources", map[string]any{
				"name": "fixture-provider-setup-" + tc.name, "kind": tc.kind,
				"config": map[string]any{"providers": []map[string]any{tc.fields}},
			})
			runID := create("/api/v1/discovery/runs", map[string]string{"source_id": sourceID})
			if err := h.srv.Drain(t.Context()); err != nil {
				t.Fatal(err)
			}
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+runID, token, nil)
			var run struct {
				Status        string `json:"status"`
				Error         string `json:"error"`
				TargetResults []struct {
					Target string `json:"target"`
					Status string `json:"status"`
					Error  string `json:"error"`
				} `json:"target_results"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &run) != nil || run.Status != "failed" {
				t.Fatalf("run receipt status=%d run=%s targets=%d", status, run.Status, len(run.TargetResults))
			}
			if tc.kind != "cloud_secret" && tc.kind != "secret_store" {
				if !strings.Contains(run.Error, tc.guidance) {
					t.Errorf("run lost setup guidance: got %q, want %q", run.Error, tc.guidance)
				}
				return
			}
			if len(run.TargetResults) != 1 {
				t.Fatalf("run omitted its provider outcome: targets=%d", len(run.TargetResults))
			}
			outcome := run.TargetResults[0]
			if !strings.Contains(run.Error, tc.guidance) || outcome.Target != tc.provider || outcome.Status != "failed" || outcome.Error != tc.guidance {
				t.Errorf("run and provider outcome lost setup guidance: run=%q target=%+v", run.Error, outcome)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("incomplete local setup attempted a provider request")
	}
}

func TestServedDiscoveryKeepsWeakKeyAuditOmissionCount(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	const omitted = 7
	run, err := h.srv.orch.RecordWeakKeyAudit(t.Context(), h.tenant, weakkey.SharedFactorReport{Distinct: weakkey.MaxSharedFactorModuli}, omitted, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+run.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(raw), "7 distinct RSA keys were left out") {
		t.Errorf("served partial audit omitted the skipped-key count: status=%d", status)
	}
}

func TestServedDiscoveryNumberedProviderFailuresKeepTransportStatus(t *testing.T) {
	const envName = "TRSTCTL_FIXTURE_PROVIDER_STATUS"
	const ref = "env:" + envName
	const marker = "fixtureopaqueproviderdetail"
	t.Setenv(envName, "fixture-provider-credential")
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"` + marker + `","message":"HTTP 429 ` + marker + `"}`))
	}))
	t.Cleanup(endpoint.Close)
	kinds := []string{"cloud_access_key", "cloud_kms_key", "load_balancer_tls"}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		bindOutboundEnvCredentialRefsFor(servedTestTenant, kinds, []string{endpoint.URL}, ref))
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))
	for _, tc := range []struct{ provider, kind string }{
		{"aws-iam", "cloud_access_key"}, {"azure-entra", "cloud_access_key"}, {"gcp-iam", "cloud_access_key"},
		{"aws-kms", "cloud_kms_key"}, {"aws-elbv2", "load_balancer_tls"}, {"f5-bigip", "load_balancer_tls"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			requestCount := requests.Load()
			create := func(path string, payload any) string {
				t.Helper()
				status, raw := secretsReq(t, h, http.MethodPost, path, token, payload)
				var response struct {
					ID string `json:"id"`
				}
				if status != http.StatusCreated || json.Unmarshal(raw, &response) != nil || response.ID == "" {
					t.Fatalf("create %s returned %d or omitted the identity", path, status)
				}
				return response.ID
			}
			provider := map[string]any{
				"provider": tc.provider, "endpoint": endpoint.URL,
				"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, endpoint.URL)},
			}
			switch tc.provider {
			case "aws-iam", "aws-kms", "aws-elbv2":
				provider["region"], provider["access_key_id_ref"], provider["secret_access_key_ref"] = "us-east-1", ref, ref
			case "gcp-iam":
				provider["token_ref"], provider["project"], provider["activity_endpoint"] = ref, "fixture-project", endpoint.URL
			default:
				provider["token_ref"] = ref
			}
			sourceID := create("/api/v1/discovery/sources", map[string]any{
				"name": "fixture-status-" + tc.provider, "kind": tc.kind,
				"config": map[string]any{"providers": []map[string]any{provider}},
			})
			runID := create("/api/v1/discovery/runs", map[string]string{"source_id": sourceID})
			if err := h.srv.Drain(t.Context()); err != nil {
				t.Fatal(err)
			}
			if requests.Load() <= requestCount {
				t.Fatal("the configured loopback transport was never reached")
			}
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+runID, token, nil)
			var run struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &run) != nil || run.Status != "failed" {
				t.Fatalf("run receipt status=%d run=%s", status, run.Status)
			}
			if !strings.Contains(run.Error, "provider 1: HTTP 403 Forbidden") || strings.Contains(run.Error, marker) || strings.Contains(run.Error, "429") {
				t.Errorf("run must retain the actual transport refusal class, got %q", run.Error)
			}
		})
	}
}
