package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedUnvaultedSecretPostureCAPSECR07EndToEnd proves CAP-SECR-07 through the
// running control plane: a served repository leak scan records redacted
// leaked_secret findings, a served cloud_secret discovery run enumerates four vault
// providers, and the read-only posture route reports multi-vault visibility plus
// configured vault-augmentation targets without returning secret values.
func TestServedUnvaultedSecretPostureCAPSECR07EndToEnd(t *testing.T) {
	repo := t.TempDir()
	rawSecret := "cap-secr-07-raw-secret-value"
	if err := writeFile(t, filepath.Join(repo, "app.env"), "API_TOKEN="+rawSecret+"\n"); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSecretRepoScanner{
		called: make(chan string, 1),
		report: secretscan.Report{
			Scanner:       "gitleaks",
			EngineVersion: secretscan.GitleaksPinnedVersion,
			RulesActive:   secretscan.GitleaksDefaultRulesActive,
			Findings: []secretscan.Finding{{
				Scanner:       "gitleaks",
				RuleID:        "generic-api-key",
				File:          filepath.Join(repo, "app.env"),
				Line:          1,
				Fingerprint:   "cap-secr-07-fingerprint",
				CredentialRef: "generic-api-key@app.env",
			}},
		},
	}

	var awsSeen, gcpSeen, azureSeen, vaultSeen []string
	awsDiscovery := servedAWSSecretsManagerDouble(map[string]string{
		"tls/aws-cap-secr-07": servedCloudCertPEM(t, "aws-cap-secr-07.example", "aws-cap-secr-07.example"),
	}, map[string]map[string]string{
		"tls/aws-cap-secr-07": {"type": "certificate"},
	}, &awsSeen)
	t.Cleanup(awsDiscovery.Close)
	gcpDiscovery := servedGCPSecretManagerDouble(map[string]string{
		"gcp-cap-secr-07": servedCloudCertPEM(t, "gcp-cap-secr-07.example", "gcp-cap-secr-07.example"),
	}, map[string]map[string]string{
		"gcp-cap-secr-07": {"type": "certificate"},
	}, &gcpSeen)
	t.Cleanup(gcpDiscovery.Close)
	azureDiscovery := servedAzureKeyVaultSecretDouble(map[string]string{
		"azure-cap-secr-07": servedCloudCertPEM(t, "azure-cap-secr-07.example", "azure-cap-secr-07.example"),
	}, map[string]map[string]string{
		"azure-cap-secr-07": {"type": "certificate"},
	}, &azureSeen)
	t.Cleanup(azureDiscovery.Close)
	vaultDiscovery := servedVaultKVDouble(map[string]string{
		"tls/vault-cap-secr-07": servedCloudCertPEM(t, "vault-cap-secr-07.example", "vault-cap-secr-07.example"),
	}, map[string]map[string]string{
		"tls/vault-cap-secr-07": {"type": "certificate"},
	}, &vaultSeen)
	t.Cleanup(vaultDiscovery.Close)

	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "gcp-token")
	t.Setenv("TRSTCTL_DISCOVERY_AZURE_KV_TOKEN", "azure-token")
	t.Setenv("TRSTCTL_DISCOVERY_VAULT_TOKEN", "vault-token")

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
		d.SecretSyncTargets = map[string]*secretsync.Target{
			"aws-secrets-manager": secretsync.NewTarget("aws-secrets-manager", capSECR07NoopPusher{}),
			"gcp-secret-manager":  secretsync.NewTarget("gcp-secret-manager", capSECR07NoopPusher{}),
			"azure-key-vault":     secretsync.NewTarget("azure-key-vault", capSECR07NoopPusher{}),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "discovery:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/repositories/github/webhook", tok, "cap-secr-07-repo", map[string]any{
		"repository":    "acme/payments",
		"checkout_path": repo,
		"ref":           "refs/heads/main",
		"commit_sha":    "cap-secr-07",
		"event":         "push",
	})
	if status != http.StatusAccepted {
		t.Fatalf("CAP-SECR-07 repository webhook status = %d, want 202; body=%s", status, body)
	}
	var repoReceipt struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(body, &repoReceipt); err != nil {
		t.Fatalf("decode CAP-SECR-07 repository receipt: %v (%s)", err, body)
	}
	deadline := time.After(5 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		select {
		case <-fake.called:
			goto repoDelivered
		case <-deadline:
			t.Fatal("CAP-SECR-07 repository scan outbox row was not delivered")
		case <-time.After(50 * time.Millisecond):
		}
	}

repoDelivered:
	var findings servedDiscoveryFindingList
	deadline = time.After(5 * time.Second)
	for {
		findings = discoveryFindingsForRun(t, h, tok, repoReceipt.RunID)
		if strings.Contains(string(findings.Raw), rawSecret) {
			t.Fatalf("CAP-SECR-07 repository findings leaked raw secret: %s", findings.Raw)
		}
		if strings.Contains(string(findings.Raw), `"kind":"leaked_secret"`) && strings.Contains(string(findings.Raw), "generic-api-key@app.env") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("CAP-SECR-07 repository scan did not record leaked_secret metadata: %s", findings.Raw)
		case <-time.After(50 * time.Millisecond):
		}
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "cap-secr-07-multi-vault",
		"kind": "cloud_secret",
		"config": map[string]any{
			"providers": []map[string]any{
				{"provider": "aws-secrets-manager", "region": "us-east-1", "endpoint": awsDiscovery.URL, "allow_private_endpoint": true, "access_key_id_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "tag_key": "type", "tag_value": "certificate"},
				{"provider": "gcp-secret-manager", "project": "trstctl-prod", "endpoint": gcpDiscovery.URL, "allow_private_endpoint": true, "token_ref": "env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "label_key": "type", "label_value": "certificate"},
				{"provider": "azure-key-vault", "vault_url": azureDiscovery.URL, "allow_private_endpoint": true, "token_ref": "env:TRSTCTL_DISCOVERY_AZURE_KV_TOKEN", "tag_key": "type", "tag_value": "certificate"},
				{"provider": "hashicorp-vault", "vault_url": vaultDiscovery.URL, "allow_private_endpoint": true, "token_ref": "env:TRSTCTL_DISCOVERY_VAULT_TOKEN", "mount": "secret", "path_prefix": "tls", "tag_key": "type", "tag_value": "certificate"},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create CAP-SECR-07 cloud_secret source: status %d body %s", status, body)
	}
	var cloudSource struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &cloudSource); err != nil {
		t.Fatalf("decode CAP-SECR-07 cloud source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": cloudSource.ID})
	if status != http.StatusCreated {
		t.Fatalf("start CAP-SECR-07 cloud discovery run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CAP-SECR-07 cloud discovery run: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/unvaulted", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("CAP-SECR-07 posture status = %d, want 200; body=%s", status, body)
	}
	if strings.Contains(string(body), rawSecret) || strings.Contains(string(body), "vault-token") || strings.Contains(string(body), "azure-token") {
		t.Fatalf("CAP-SECR-07 posture leaked secret material: %s", body)
	}
	var posture struct {
		Capability string `json:"capability"`
		Served     bool   `json:"served"`
		Summary    struct {
			RepositorySources       int `json:"repository_sources"`
			CloudSecretSources      int `json:"cloud_secret_sources"`
			VaultProvidersSupported int `json:"vault_providers_supported"`
			VaultProvidersVisible   int `json:"vault_providers_visible"`
			SyncTargetsConfigured   int `json:"sync_targets_configured"`
			LeakedSecretFindings    int `json:"leaked_secret_findings"`
		} `json:"summary"`
		DetectionSources []struct {
			ID              string `json:"id"`
			SourceKind      string `json:"source_kind"`
			ConfiguredCount int    `json:"configured_count"`
			FindingsKind    string `json:"findings_kind"`
		} `json:"detection_sources"`
		VaultProviders []struct {
			ID                   string `json:"id"`
			DiscoveryConfigured  bool   `json:"discovery_configured"`
			DiscoverySourceCount int    `json:"discovery_source_count"`
			SyncSupported        bool   `json:"sync_supported"`
			SyncConfigured       bool   `json:"sync_configured"`
		} `json:"vault_providers"`
		ConfiguredVaults      []string `json:"configured_vaults"`
		ConfiguredSyncTargets []string `json:"configured_sync_targets"`
		EvidenceRefs          []string `json:"evidence_refs"`
		Residuals             []string `json:"residuals"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode CAP-SECR-07 posture: %v (%s)", err, body)
	}
	if posture.Capability != "CAP-SECR-07" || !posture.Served {
		t.Fatalf("CAP-SECR-07 posture = %+v, want served CAP-SECR-07", posture)
	}
	if posture.Summary.RepositorySources != 1 || posture.Summary.CloudSecretSources != 1 || posture.Summary.VaultProvidersSupported != 4 || posture.Summary.VaultProvidersVisible != 4 || posture.Summary.SyncTargetsConfigured != 3 || posture.Summary.LeakedSecretFindings != 1 {
		t.Fatalf("CAP-SECR-07 summary = %+v, want repo scan + four vaults + three sync targets + one leak", posture.Summary)
	}
	for _, want := range []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault", "hashicorp-vault"} {
		if !containsServerString(posture.ConfiguredVaults, want) || !unvaultedVaultProviderVisible(posture.VaultProviders, want) {
			t.Fatalf("CAP-SECR-07 vault visibility missing %q: vaults=%v providers=%+v", want, posture.ConfiguredVaults, posture.VaultProviders)
		}
	}
	for _, want := range []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault"} {
		if !containsServerString(posture.ConfiguredSyncTargets, want) {
			t.Fatalf("CAP-SECR-07 sync targets missing %q: %v", want, posture.ConfiguredSyncTargets)
		}
	}
	if !unvaultedDetectionSource(posture.DetectionSources, "repositories", secretscan.RepositorySourceKind, 1) {
		t.Fatalf("CAP-SECR-07 detection sources missing served repository count: %+v", posture.DetectionSources)
	}
	if len(posture.EvidenceRefs) == 0 || len(posture.Residuals) == 0 {
		t.Fatalf("CAP-SECR-07 posture must expose evidence and residuals: %+v", posture)
	}
}

type capSECR07NoopPusher struct{}

func (capSECR07NoopPusher) Push(context.Context, string, []byte) error { return nil }

func writeFile(t *testing.T, path, body string) error {
	t.Helper()
	return os.WriteFile(path, []byte(body), 0o600)
}

func unvaultedVaultProviderVisible(providers []struct {
	ID                   string `json:"id"`
	DiscoveryConfigured  bool   `json:"discovery_configured"`
	DiscoverySourceCount int    `json:"discovery_source_count"`
	SyncSupported        bool   `json:"sync_supported"`
	SyncConfigured       bool   `json:"sync_configured"`
}, want string) bool {
	for _, p := range providers {
		if p.ID == want && p.DiscoveryConfigured && p.DiscoverySourceCount == 1 {
			return true
		}
	}
	return false
}

func unvaultedDetectionSource(sources []struct {
	ID              string `json:"id"`
	SourceKind      string `json:"source_kind"`
	ConfiguredCount int    `json:"configured_count"`
	FindingsKind    string `json:"findings_kind"`
}, id, kind string, count int) bool {
	for _, src := range sources {
		if src.ID == id && src.SourceKind == kind && src.ConfiguredCount == count && src.FindingsKind == "leaked_secret" {
			return true
		}
	}
	return false
}
