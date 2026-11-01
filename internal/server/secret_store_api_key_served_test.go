// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// a172Token assembles a credential-shaped fixture at run time so the
// repository's own leak scanner never sees a token-shaped literal.
func a172Token(prefix, body string, n int) string {
	return prefix + strings.Repeat(body, n/len(body)+1)[:n]
}

// a172VaultKVDouble serves KV v2 secrets under the "ci" prefix with arbitrary
// fields, so a finding can name the field it sat in.
func a172VaultKVDouble(secrets map[string]map[string]string, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Vault-Token") != "vault-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "LIST" && r.URL.Path == "/v1/secret/metadata/ci":
			var keys []string
			for name := range secrets {
				keys = append(keys, strings.TrimPrefix(name, "ci/"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"current_version": 1, "oldest_version": 1, "updated_time": "2026-10-31T00:00:00Z",
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": secrets[name], "metadata": map[string]any{}}})
		default:
			http.Error(w, "unexpected Vault operation", http.StatusBadRequest)
		}
	}))
}

// A172 Done-when: native API-key scanning of external secret stores. A
// secret_store source with content inspection reads AWS Secrets Manager,
// Google Secret Manager, Azure Key Vault and Vault KV and records each API
// key, token and private key it finds as a secret_store_api_key finding: the
// rule, the field, a masked display and a fingerprint that is equal wherever
// the same credential is stored. The value appears nowhere in the findings or
// the event log, and a source without content inspection fetches no value and
// finds no credential.
func TestServedSecretStoreAPIKeyScanning(t *testing.T) {
	githubPAT := a172Token("gh"+"p_", "A172srv9", 36)
	slack := a172Token("xo"+"xb-", "17221-", 40)
	awsID := "AK" + "IA" + "A172SERVEDKEY001"
	awsSecret := a172Token("", "A172+served/Key", 40)
	gitlab := a172Token("gl"+"pat-", "A172shared", 26)
	saKey := "-----BEGIN " + "PRIVATE KEY-----\nMIIEvA172servedserviceaccount\n-----END " + "PRIVATE KEY-----\n"
	raw := []string{githubPAT, slack, awsSecret, gitlab, "MIIEvA172served"}

	appProd, _ := json.Marshal(map[string]string{"github": githubPAT, "slack_bot": slack, "aws_access_key_id": awsID, "aws_secret_access_key": awsSecret})
	saJSON, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "a172", "private_key_id": "k1",
		"private_key": saKey, "client_email": "deployer@a172.iam.gserviceaccount.com"})
	var awsSeen, gcpSeen, azureSeen, vaultSeen []string
	aws := servedAWSSecretsManagerDouble(map[string]string{"app/prod": string(appProd), "app/db": "correct horse battery staple"}, nil, &awsSeen)
	t.Cleanup(aws.Close)
	gcp := servedGCPSecretManagerDouble(map[string]string{"deployer-key": string(saJSON)}, nil, &gcpSeen)
	t.Cleanup(gcp.Close)
	azure := servedAzureKeyVaultSecretDouble(map[string]string{"gitlab-token": "GITLAB_TOKEN=" + gitlab + "\n"}, nil, &azureSeen)
	t.Cleanup(azure.Close)
	vault := a172VaultKVDouble(map[string]map[string]string{"ci/gitlab": {"token": gitlab, "user": "ci-bot"}}, &vaultSeen)
	t.Cleanup(vault.Close)
	t.Setenv("TRSTCTL_A172_AWS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_A172_AWS_SECRET", "SECRET")
	t.Setenv("TRSTCTL_A172_GCP_TOKEN", "gcp-token")
	t.Setenv("TRSTCTL_A172_AZURE_TOKEN", "azure-token")
	t.Setenv("TRSTCTL_A172_VAULT_TOKEN", "vault-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A172_AWS_KEY_ID", "env:TRSTCTL_A172_AWS_SECRET",
		"env:TRSTCTL_A172_GCP_TOKEN", "env:TRSTCTL_A172_AZURE_TOKEN", "env:TRSTCTL_A172_VAULT_TOKEN"))
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))

	providers := func(inspect bool) []map[string]any {
		private := func(url string) map[string]any {
			return map[string]any{"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, url)}, "inspect_content": inspect}
		}
		with := func(base map[string]any, extra map[string]any) map[string]any {
			for k, v := range extra {
				base[k] = v
			}
			return base
		}
		return []map[string]any{
			with(private(aws.URL), map[string]any{"provider": "aws-secrets-manager", "region": "us-east-1", "endpoint": aws.URL, // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
				"access_key_id_ref": "env:TRSTCTL_A172_AWS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_A172_AWS_SECRET"}),
			with(private(gcp.URL), map[string]any{"provider": "gcp-secret-manager", "project": "p", "endpoint": gcp.URL, "token_ref": "env:TRSTCTL_A172_GCP_TOKEN"}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			with(private(azure.URL), map[string]any{"provider": "azure-key-vault", "vault_url": azure.URL, "token_ref": "env:TRSTCTL_A172_AZURE_TOKEN"}),             // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			with(private(vault.URL), map[string]any{"provider": "hashicorp-vault", "vault_url": vault.URL, "mount": "secret", "path_prefix": "ci", // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
				"token_ref": "env:TRSTCTL_A172_VAULT_TOKEN"}),
		}
	}
	runSource := func(name string, inspect bool) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
			"name": name, "kind": "secret_store", "config": map[string]any{"providers": providers(inspect)}})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID}); status != http.StatusCreated {
			t.Fatalf("run %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain %s: %v", name, err)
		}
		return source.ID
	}
	type credentialRow struct {
		ID          string         `json:"id"`
		SourceID    string         `json:"source_id"`
		Kind        string         `json:"kind"`
		Ref         string         `json:"ref"`
		Fingerprint string         `json:"fingerprint"`
		RiskScore   int            `json:"risk_score"`
		Metadata    map[string]any `json:"metadata"`
	}
	credentials := func(sourceID string) ([]credentialRow, []byte) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?kind=secret_store_api_key&limit=100", tok, nil)
		var list struct {
			Items []credentialRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		var out []credentialRow
		for _, f := range list.Items {
			if f.SourceID == sourceID {
				out = append(out, f)
			}
		}
		return out, body
	}

	sourceID := runSource("stores-inspected", true)
	rows, body := credentials(sourceID)
	byKey := map[string]credentialRow{}
	for _, f := range rows {
		byKey[f.Metadata["provider"].(string)+"/"+f.Metadata["rule"].(string)] = f
	}
	want := map[string]struct{ field, kind, masked string }{
		"aws-secrets-manager/github_personal_access_token": {"github", "personal_access_token", "ghp_…(40 chars)"},
		"aws-secrets-manager/slack_token":                  {"slack_bot", "api_token", "xoxb-…(45 chars)"},
		"aws-secrets-manager/aws_access_key_id":            {"aws_access_key_id", "api_key", "AKIA…(20 chars)"},
		"aws-secrets-manager/aws_secret_access_key":        {"aws_secret_access_key", "api_key", "…(40 chars)"},
		"gcp-secret-manager/gcp_service_account_key":       {"private_key", "api_key", "service account deployer@a172.iam.gserviceaccount.com"},
		"azure-key-vault/gitlab_token":                     {"", "personal_access_token", "glpat-…(32 chars)"},
		"hashicorp-vault/gitlab_token":                     {"token", "personal_access_token", "glpat-…(32 chars)"},
	}
	if len(rows) != len(want) {
		t.Fatalf("credential findings = %d, want %d: %s", len(rows), len(want), body)
	}
	for key, w := range want {
		f, ok := byKey[key]
		if !ok || f.Metadata["credential_kind"] != w.kind || f.Metadata["masked"] != w.masked || f.Metadata["content_inspected"] != true ||
			(w.field != "" && f.Metadata["field"] != w.field) || len(f.Fingerprint) != 64 || f.RiskScore == 0 {
			t.Fatalf("%s = %+v, want %+v", key, f, w)
		}
	}
	if byKey["gcp-secret-manager/gcp_service_account_key"].Metadata["principal"] != "deployer@a172.iam.gserviceaccount.com" {
		t.Fatalf("service account principal = %+v", byKey["gcp-secret-manager/gcp_service_account_key"].Metadata)
	}
	if a, v := byKey["azure-key-vault/gitlab_token"], byKey["hashicorp-vault/gitlab_token"]; a.Fingerprint != v.Fingerprint || a.Ref == v.Ref {
		t.Fatalf("the same GitLab token in two stores: azure %s %s, vault %s %s", a.Ref, a.Fingerprint, v.Ref, v.Fingerprint)
	}
	for _, value := range raw {
		if bytes.Contains(body, []byte(value)) {
			t.Fatal("the findings response carries a credential value")
		}
	}
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		for _, value := range raw {
			if bytes.Contains(e.Data, []byte(value)) {
				t.Fatalf("event %s carries a credential value", e.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Without content inspection nothing is fetched and nothing is found.
	awsSeen, azureSeen, vaultSeen = nil, nil, nil
	metadataOnly := runSource("stores-metadata-only", false)
	if rows, _ := credentials(metadataOnly); len(rows) != 0 {
		t.Fatalf("metadata-only source found credentials: %+v", rows)
	}
	for _, target := range awsSeen {
		if target == "secretsmanager.GetSecretValue" {
			t.Fatal("a metadata-only source fetched an AWS secret value")
		}
	}
	for _, call := range append(azureSeen, vaultSeen...) {
		if strings.Contains(call, "secrets/") || strings.Contains(call, "/v1/secret/data/") {
			t.Fatalf("a metadata-only source fetched a secret value: %s", call)
		}
	}
	if len(gcpSeen) == 0 || len(vaultSeen) == 0 {
		t.Fatal("the stores were not read")
	}
}
