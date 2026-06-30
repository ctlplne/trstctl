package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
)

// TestServedSecretSyncPushesBroadCatalogCAPSECR03 is the SEC-06/CAP-SECR-03 proof:
// a stored secret changes once in trstctl, then the served sync API pushes it through
// the broad table-stakes catalog: AWS, GCP, Azure, GitHub, GitLab, Vercel, and a
// generic CI endpoint. The response and event log contain delivery metadata only;
// each fixture is read back over its own API-facing recorder to prove the external
// write happened.
func TestServedSecretSyncPushesBroadCatalogCAPSECR03(t *testing.T) {
	gh := newGitHubActionsSyncFixture(t)
	aws := newAWSSecretsManagerSyncFixture(t)
	gcp := newGCPSecretManagerSyncFixture(t)
	azure := newAzureKeyVaultSyncFixture(t)
	gitlab := newGitLabCISyncFixture(t)
	vercel := newVercelSyncFixture(t)
	ci := newCISyncFixture(t)
	k8s := newKubernetesSecretSyncFixture(t)

	ghPusher, err := secretsync.NewGitHubActionsPusher(secretsync.GitHubActionsConfig{
		Endpoint: gh.URL(), HTTPClient: gh.Client(), Owner: "ctlplne", Repo: "payments", Token: []byte("github-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	awsPusher, err := secretsync.NewAWSSecretsManagerPusher(secretsync.AWSSecretsManagerConfig{
		Endpoint: aws.URL(), HTTPClient: aws.Client(), Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"),
	})
	if err != nil {
		t.Fatal(err)
	}
	gcpPusher, err := secretsync.NewGCPSecretManagerPusher(secretsync.GCPSecretManagerConfig{
		Endpoint: gcp.URL(), HTTPClient: gcp.Client(), Project: "trstctl-prod", BearerToken: []byte("gcp-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	azurePusher, err := secretsync.NewAzureKeyVaultPusher(secretsync.AzureKeyVaultConfig{
		Endpoint: azure.URL(), HTTPClient: azure.Client(), BearerToken: []byte("azure-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	gitlabPusher, err := secretsync.NewGitLabCIPusher(secretsync.GitLabCIConfig{
		Endpoint: gitlab.URL(), HTTPClient: gitlab.Client(), ProjectID: "payments", Token: []byte("gitlab-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	vercelPusher, err := secretsync.NewVercelPusher(secretsync.VercelConfig{
		Endpoint: vercel.URL(), HTTPClient: vercel.Client(), ProjectID: "payments", Token: []byte("vercel-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ciPusher, err := secretsync.NewCIPusher(secretsync.CIPusherConfig{
		Endpoint: ci.URL(), HTTPClient: ci.Client(), BearerToken: []byte("ci-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	k8sPusher, err := secretsync.NewKubernetesPusher(secretsync.KubernetesConfig{
		Endpoint: k8s.URL(), HTTPClient: k8s.Client(), Namespace: "apps", BearerToken: []byte("k8s-token"),
	})
	if err != nil {
		t.Fatal(err)
	}

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"github-actions":      secretsync.NewGitHubActionsTarget(ghPusher),
				"aws-secrets-manager": secretsync.NewAWSSecretsManagerTarget(awsPusher),
				"gcp-secret-manager":  secretsync.NewGCPSecretManagerTarget(gcpPusher),
				"azure-key-vault":     secretsync.NewAzureKeyVaultTarget(azurePusher),
				"gitlab-ci":           secretsync.NewGitLabCITarget(gitlabPusher),
				"vercel-netlify":      secretsync.NewVercelTarget(vercelPusher),
				"ci":                  secretsync.NewCITarget(ciPusher),
				"kubernetes":          secretsync.NewKubernetesTarget(k8sPusher),
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "sync/source", "value": "sync-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create sync source: status %d body %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/syncs/targets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list sync targets: status %d body %s", status, body)
	}
	var catalog struct {
		Capability string `json:"capability"`
		Targets    []struct {
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			Configured   bool     `json:"configured"`
			Capabilities []string `json:"capabilities"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		t.Fatalf("decode sync target catalog: %v (%s)", err, body)
	}
	if catalog.Capability != "CAP-SECR-03" {
		t.Fatalf("catalog capability = %q, want CAP-SECR-03", catalog.Capability)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/kubernetes-operator", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("kubernetes operator posture: status %d body %s", status, body)
	}
	var operatorPosture struct {
		Capability      string   `json:"capability"`
		Served          bool     `json:"served"`
		ReloadWorkloads []string `json:"reload_workloads"`
		CRDs            []struct {
			Kind   string   `json:"kind"`
			Plural string   `json:"plural"`
			Status string   `json:"status"`
			Owns   []string `json:"owns"`
		} `json:"crds"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(body, &operatorPosture); err != nil {
		t.Fatalf("decode kubernetes operator posture: %v (%s)", err, body)
	}
	if operatorPosture.Capability != "CAP-SECR-04" || !operatorPosture.Served {
		t.Fatalf("kubernetes operator posture = %+v, want served CAP-SECR-04", operatorPosture)
	}
	assertKubernetesOperatorPosture(t, operatorPosture)
	if strings.Contains(string(body), "sync-v1") || strings.Contains(string(body), "github-token") {
		t.Fatalf("kubernetes operator posture leaked secret material: %s", body)
	}

	syncCases := []struct {
		target string
		remote string
		read   func() string
	}{
		{target: "github-actions", remote: "DB_PASSWORD", read: func() string { return gh.value("ctlplne", "payments", "DB_PASSWORD") }},
		{target: "aws-secrets-manager", remote: "prod/db/password", read: func() string { return aws.value("prod/db/password") }},
		{target: "gcp-secret-manager", remote: "db-password", read: func() string { return gcp.value("trstctl-prod", "db-password") }},
		{target: "azure-key-vault", remote: "db-password", read: func() string { return azure.value("db-password") }},
		{target: "gitlab-ci", remote: "DB_PASSWORD", read: func() string { return gitlab.value("payments", "DB_PASSWORD") }},
		{target: "vercel-netlify", remote: "DB_PASSWORD", read: func() string { return vercel.value("payments", "DB_PASSWORD") }},
		{target: "ci", remote: "DB_PASSWORD", read: func() string { return ci.value("ci", "DB_PASSWORD") }},
		{target: "kubernetes", remote: "db-password", read: func() string { return k8s.value("apps", "db-password") }},
	}
	assertCatalogTargetsConfigured(t, catalog.Targets, syncCases)

	for _, tc := range syncCases {
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "sec06-"+tc.target,
			map[string]any{"name": "sync/source", "target": tc.target, "remote_key": tc.remote})
		if status != http.StatusOK {
			t.Fatalf("%s sync: status %d body %s", tc.target, status, body)
		}
		var resp struct {
			Name      string `json:"name"`
			Target    string `json:"target"`
			RemoteKey string `json:"remote_key"`
			Enqueued  bool   `json:"enqueued"`
			Delivered bool   `json:"delivered"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode %s response: %v (%s)", tc.target, err, body)
		}
		if resp.Name != "sync/source" || resp.Target != tc.target || resp.RemoteKey != tc.remote || !resp.Enqueued || !resp.Delivered {
			t.Fatalf("%s sync response = %+v", tc.target, resp)
		}
		if strings.Contains(string(body), "sync-v1") {
			t.Fatalf("%s sync response leaked the secret value: %s", tc.target, body)
		}
		if got := tc.read(); got != "sync-v1" {
			t.Fatalf("%s destination readback = %q, want sync-v1", tc.target, got)
		}
	}

	// Replaying a sync with the same Idempotency-Key returns the cached result and
	// does not push a second write to the destination.
	before := gh.count("ctlplne", "payments", "DB_PASSWORD")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "sec06-github-actions",
		map[string]any{"name": "sync/source", "target": "github-actions", "remote_key": "DB_PASSWORD"})
	if status != http.StatusOK {
		t.Fatalf("github replay: status %d body %s", status, body)
	}
	if after := gh.count("ctlplne", "payments", "DB_PASSWORD"); after != before {
		t.Fatalf("idempotent replay wrote GitHub %d times, want unchanged %d", after, before)
	}
	if !h.hasEvent(t, "secret.sync.delivered") {
		t.Fatal("no secret.sync.delivered event recorded")
	}
	if h.logContains(t, "sync-v1") {
		t.Fatal("secret sync event log leaked the synced secret value")
	}
}

// TestServedCloudSecretManagerIntegrationCAPSEC04EndToEnd proves the Secrets
// category CAP-SEC-04 surface: configured cloud_secret discovery executes against
// AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and HashiCorp Vault KV;
// stored-secret sync writes to AWS/GCP/Azure through the sealed outbox; and the
// served posture route/CLI-backed API reports only metadata.
func TestServedCloudSecretManagerIntegrationCAPSEC04EndToEnd(t *testing.T) {
	awsSync := newAWSSecretsManagerSyncFixture(t)
	gcpSync := newGCPSecretManagerSyncFixture(t)
	azureSync := newAzureKeyVaultSyncFixture(t)
	awsPusher, err := secretsync.NewAWSSecretsManagerPusher(secretsync.AWSSecretsManagerConfig{
		Endpoint: awsSync.URL(), HTTPClient: awsSync.Client(), Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"),
	})
	if err != nil {
		t.Fatal(err)
	}
	gcpPusher, err := secretsync.NewGCPSecretManagerPusher(secretsync.GCPSecretManagerConfig{
		Endpoint: gcpSync.URL(), HTTPClient: gcpSync.Client(), Project: "trstctl-prod", BearerToken: []byte("gcp-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	azurePusher, err := secretsync.NewAzureKeyVaultPusher(secretsync.AzureKeyVaultConfig{
		Endpoint: azureSync.URL(), HTTPClient: azureSync.Client(), BearerToken: []byte("azure-token"),
	})
	if err != nil {
		t.Fatal(err)
	}

	var awsSeen, gcpSeen, azureSeen, vaultSeen []string
	awsDiscovery := servedAWSSecretsManagerDouble(map[string]string{
		"tls/aws-cap-sec-04": servedCloudCertPEM(t, "aws-cap-sec-04.example", "aws-cap-sec-04.example"),
	}, map[string]map[string]string{
		"tls/aws-cap-sec-04": {"type": "certificate"},
	}, &awsSeen)
	t.Cleanup(awsDiscovery.Close)
	gcpDiscovery := servedGCPSecretManagerDouble(map[string]string{
		"gcp-cap-sec-04": servedCloudCertPEM(t, "gcp-cap-sec-04.example", "gcp-cap-sec-04.example"),
	}, map[string]map[string]string{
		"gcp-cap-sec-04": {"type": "certificate"},
	}, &gcpSeen)
	t.Cleanup(gcpDiscovery.Close)
	azureDiscovery := servedAzureKeyVaultSecretDouble(map[string]string{
		"azure-cap-sec-04": servedCloudCertPEM(t, "azure-cap-sec-04.example", "azure-cap-sec-04.example"),
	}, map[string]map[string]string{
		"azure-cap-sec-04": {"type": "certificate"},
	}, &azureSeen)
	t.Cleanup(azureDiscovery.Close)
	vaultDiscovery := servedVaultKVDouble(map[string]string{
		"tls/vault-cap-sec-04": servedCloudCertPEM(t, "vault-cap-sec-04.example", "vault-cap-sec-04.example"),
	}, map[string]map[string]string{
		"tls/vault-cap-sec-04": {"type": "certificate"},
	}, &vaultSeen)
	t.Cleanup(vaultDiscovery.Close)
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "SECRET")
	t.Setenv("TRSTCTL_DISCOVERY_GCP_SM_TOKEN", "gcp-token")
	t.Setenv("TRSTCTL_DISCOVERY_AZURE_KV_TOKEN", "azure-token")
	t.Setenv("TRSTCTL_DISCOVERY_VAULT_TOKEN", "vault-token")

	h := newServedHarness(t, config.Protocols{},
		withSecretsEnabled(t, nil),
		func(d *Deps) {
			d.SecretSyncTargets = map[string]*secretsync.Target{
				"aws-secrets-manager": secretsync.NewAWSSecretsManagerTarget(awsPusher),
				"gcp-secret-manager":  secretsync.NewGCPSecretManagerTarget(gcpPusher),
				"azure-key-vault":     secretsync.NewAzureKeyVaultTarget(azurePusher),
			}
		},
	)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "cap-sec-04-cloud-secret-managers",
		"kind": "cloud_secret",
		"config": map[string]any{
			"providers": []map[string]any{
				{
					"provider":               "aws-secrets-manager",
					"region":                 "us-east-1",
					"endpoint":               awsDiscovery.URL,
					"allow_private_endpoint": true,
					"access_key_id_ref":      "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID",
					"secret_access_key_ref":  "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY",
					"tag_key":                "type",
					"tag_value":              "certificate",
				},
				{
					"provider":               "gcp-secret-manager",
					"project":                "trstctl-prod",
					"endpoint":               gcpDiscovery.URL,
					"allow_private_endpoint": true,
					"token_ref":              "env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN",
					"label_key":              "type",
					"label_value":            "certificate",
				},
				{
					"provider":               "azure-key-vault",
					"vault_url":              azureDiscovery.URL,
					"allow_private_endpoint": true,
					"token_ref":              "env:TRSTCTL_DISCOVERY_AZURE_KV_TOKEN",
					"tag_key":                "type",
					"tag_value":              "certificate",
				},
				{
					"provider":               "hashicorp-vault",
					"vault_url":              vaultDiscovery.URL,
					"allow_private_endpoint": true,
					"token_ref":              "env:TRSTCTL_DISCOVERY_VAULT_TOKEN",
					"mount":                  "secret",
					"path_prefix":            "tls",
					"tag_key":                "type",
					"tag_value":              "certificate",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create CAP-SEC-04 discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode discovery source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("start CAP-SEC-04 discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode discovery run: %v (%s)", err, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CAP-SEC-04 discovery run: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get CAP-SEC-04 discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed discovery run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 4 || completed.Discovered != 4 || completed.Failed != 0 {
		t.Fatalf("CAP-SEC-04 discovery run = %+v, want four successful cloud secret-manager findings", completed)
	}
	findings := discoveryFindingsForRun(t, h, tok, queued.ID)
	for _, leak := range []string{"SECRET", "gcp-token", "azure-token", "vault-token"} {
		if strings.Contains(string(findings.Raw), leak) {
			t.Fatalf("CAP-SEC-04 findings leaked %q: %s", leak, findings.Raw)
		}
	}
	seenProviders := map[string]bool{}
	for _, f := range findings.Items {
		var meta map[string]any
		if err := json.Unmarshal(f.Metadata, &meta); err != nil {
			t.Fatalf("decode CAP-SEC-04 finding metadata: %v (%s)", err, f.Metadata)
		}
		if provider, _ := meta["provider"].(string); provider != "" {
			seenProviders[provider] = true
		}
	}
	for _, provider := range []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault", "hashicorp-vault"} {
		if !seenProviders[provider] {
			t.Fatalf("missing provider %s in CAP-SEC-04 findings: %+v", provider, seenProviders)
		}
	}
	for _, method := range azureSeen {
		if !strings.HasPrefix(method, "GET ") {
			t.Fatalf("Azure Key Vault discovery issued %s; it must stay GET-only", method)
		}
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok,
		map[string]any{"name": "cap-sec-04/source", "value": "cloud-sync-v1"})
	if status != http.StatusCreated {
		t.Fatalf("create CAP-SEC-04 sync source: status %d body %s", status, body)
	}
	for _, tc := range []struct {
		target string
		remote string
		read   func() string
	}{
		{target: "aws-secrets-manager", remote: "cap-sec-04/aws", read: func() string { return awsSync.value("cap-sec-04/aws") }},
		{target: "gcp-secret-manager", remote: "cap-sec-04-gcp", read: func() string { return gcpSync.value("trstctl-prod", "cap-sec-04-gcp") }},
		{target: "azure-key-vault", remote: "cap-sec-04-azure", read: func() string { return azureSync.value("cap-sec-04-azure") }},
	} {
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "cap-sec-04-"+tc.target,
			map[string]any{"name": "cap-sec-04/source", "target": tc.target, "remote_key": tc.remote})
		if status != http.StatusOK {
			t.Fatalf("%s CAP-SEC-04 sync: status %d body %s", tc.target, status, body)
		}
		if strings.Contains(string(body), "cloud-sync-v1") {
			t.Fatalf("%s CAP-SEC-04 sync leaked secret value: %s", tc.target, body)
		}
		if got := tc.read(); got != "cloud-sync-v1" {
			t.Fatalf("%s CAP-SEC-04 sync readback = %q, want cloud-sync-v1", tc.target, got)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/cloud-secret-managers", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("CAP-SEC-04 posture: status %d body %s", status, body)
	}
	for _, leak := range []string{"cloud-sync-v1", "SECRET", "gcp-token", "azure-token", "vault-token"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("CAP-SEC-04 posture leaked %q: %s", leak, body)
		}
	}
	var posture struct {
		Capability string `json:"capability"`
		Served     bool   `json:"served"`
		Summary    struct {
			DiscoveryConfigured   int `json:"discovery_configured"`
			SyncConfigured        int `json:"sync_configured"`
			ConfiguredConnections int `json:"configured_connections"`
		} `json:"summary"`
		Providers []struct {
			ID                   string   `json:"id"`
			DiscoverySupported   bool     `json:"discovery_supported"`
			DiscoveryConfigured  bool     `json:"discovery_configured"`
			DiscoverySourceCount int      `json:"discovery_source_count"`
			SyncSupported        bool     `json:"sync_supported"`
			SyncConfigured       bool     `json:"sync_configured"`
			EvidenceRefs         []string `json:"evidence_refs"`
		} `json:"providers"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode CAP-SEC-04 posture: %v (%s)", err, body)
	}
	if posture.Capability != "CAP-SEC-04" || !posture.Served {
		t.Fatalf("CAP-SEC-04 posture = %+v, want served CAP-SEC-04", posture)
	}
	if posture.Summary.DiscoveryConfigured != 4 || posture.Summary.SyncConfigured != 3 || posture.Summary.ConfiguredConnections != 7 {
		t.Fatalf("CAP-SEC-04 summary = %+v, want four discovery providers and three sync targets", posture.Summary)
	}
	providers := map[string]struct {
		DiscoverySupported   bool
		DiscoveryConfigured  bool
		DiscoverySourceCount int
		SyncSupported        bool
		SyncConfigured       bool
		EvidenceRefs         []string
	}{}
	for _, p := range posture.Providers {
		providers[p.ID] = struct {
			DiscoverySupported   bool
			DiscoveryConfigured  bool
			DiscoverySourceCount int
			SyncSupported        bool
			SyncConfigured       bool
			EvidenceRefs         []string
		}{
			DiscoverySupported:   p.DiscoverySupported,
			DiscoveryConfigured:  p.DiscoveryConfigured,
			DiscoverySourceCount: p.DiscoverySourceCount,
			SyncSupported:        p.SyncSupported,
			SyncConfigured:       p.SyncConfigured,
			EvidenceRefs:         p.EvidenceRefs,
		}
	}
	for _, id := range []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault"} {
		p := providers[id]
		if !p.DiscoverySupported || !p.DiscoveryConfigured || p.DiscoverySourceCount != 1 || !p.SyncSupported || !p.SyncConfigured {
			t.Fatalf("CAP-SEC-04 provider %s = %+v, want discovery+sync configured", id, p)
		}
	}
	vault := providers["hashicorp-vault"]
	if !vault.DiscoverySupported || !vault.DiscoveryConfigured || vault.DiscoverySourceCount != 1 || vault.SyncSupported || vault.SyncConfigured {
		t.Fatalf("CAP-SEC-04 Vault posture = %+v, want read-only discovery configured and no sync target", vault)
	}
	requireString(t, providers["azure-key-vault"].EvidenceRefs, "internal/discovery/cloudsecret/azurekv/azurekv.go", "CAP-SEC-04 Azure evidence")
	requireString(t, posture.EvidenceRefs, "internal/server/secrets_sync_served_test.go", "CAP-SEC-04 evidence refs")
	requireString(t, posture.EvidenceRefs, "internal/server/discovery_served_test.go", "CAP-SEC-04 evidence refs")
}

func assertKubernetesOperatorPosture(t *testing.T, posture struct {
	Capability      string   `json:"capability"`
	Served          bool     `json:"served"`
	ReloadWorkloads []string `json:"reload_workloads"`
	CRDs            []struct {
		Kind   string   `json:"kind"`
		Plural string   `json:"plural"`
		Status string   `json:"status"`
		Owns   []string `json:"owns"`
	} `json:"crds"`
	EvidenceRefs []string `json:"evidence_refs"`
}) {
	t.Helper()
	requireString(t, posture.ReloadWorkloads, "Deployment", "operator reload workloads")
	requireString(t, posture.ReloadWorkloads, "StatefulSet", "operator reload workloads")
	requireString(t, posture.ReloadWorkloads, "DaemonSet", "operator reload workloads")
	requireString(t, posture.EvidenceRefs, "internal/operator/secretsync.go", "operator evidence refs")
	requireString(t, posture.EvidenceRefs, "deploy/operator/crd.yaml", "operator evidence refs")
	for _, crd := range posture.CRDs {
		if crd.Kind != "TrstctlSecretSync" {
			continue
		}
		if crd.Plural != "trstctlsecretsyncs" || crd.Status != "served" {
			t.Fatalf("TrstctlSecretSync CRD = %+v, want served trstctlsecretsyncs", crd)
		}
		requireString(t, crd.Owns, "Kubernetes Secret data", "TrstctlSecretSync ownership")
		requireString(t, crd.Owns, "status.contentHash", "TrstctlSecretSync ownership")
		return
	}
	t.Fatalf("operator posture missing TrstctlSecretSync CRD: %+v", posture.CRDs)
}

func requireString(t *testing.T, haystack []string, needle, label string) {
	t.Helper()
	for _, got := range haystack {
		if got == needle {
			return
		}
	}
	t.Fatalf("%s missing %q from %v", label, needle, haystack)
}

func assertCatalogTargetsConfigured(t *testing.T, targets []struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Configured   bool     `json:"configured"`
	Capabilities []string `json:"capabilities"`
}, syncCases []struct {
	target string
	remote string
	read   func() string
}) {
	t.Helper()
	byID := map[string]struct {
		Name         string
		Configured   bool
		Capabilities []string
	}{}
	for _, target := range targets {
		byID[target.ID] = struct {
			Name         string
			Configured   bool
			Capabilities []string
		}{Name: target.Name, Configured: target.Configured, Capabilities: target.Capabilities}
	}
	for _, tc := range syncCases {
		got, ok := byID[tc.target]
		if !ok {
			t.Fatalf("sync catalog missing target %s", tc.target)
		}
		if got.Name == "" || !got.Configured || len(got.Capabilities) == 0 {
			t.Fatalf("sync catalog target %s = %+v, want named configured target with capabilities", tc.target, got)
		}
	}
}

type gitHubActionsSyncFixture struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
	counts map[string]int
}

func newGitHubActionsSyncFixture(t *testing.T) *gitHubActionsSyncFixture {
	t.Helper()
	f := &gitHubActionsSyncFixture{t: t, values: map[string]string{}, counts: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *gitHubActionsSyncFixture) URL() string          { return f.server.URL }
func (f *gitHubActionsSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *gitHubActionsSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer github-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "repos" || parts[3] != "actions" || parts[4] != "secrets" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.EncodedValue)
	if err != nil {
		http.Error(w, "encoded_value", http.StatusBadRequest)
		return
	}
	key := parts[1] + "/" + parts[2] + "/" + parts[5]
	f.mu.Lock()
	f.values[key] = string(decoded)
	f.counts[key]++
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *gitHubActionsSyncFixture) value(owner, repo, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[owner+"/"+repo+"/"+name]
}

func (f *gitHubActionsSyncFixture) count(owner, repo, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[owner+"/"+repo+"/"+name]
}

type awsSecretsManagerSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newAWSSecretsManagerSyncFixture(t *testing.T) *awsSecretsManagerSyncFixture {
	t.Helper()
	f := &awsSecretsManagerSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *awsSecretsManagerSyncFixture) URL() string          { return f.server.URL }
func (f *awsSecretsManagerSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *awsSecretsManagerSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") == "" || r.Header.Get("X-Amz-Date") == "" {
		http.Error(w, "missing sigv4", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Name         string `json:"Name"`
		SecretBinary string `json:"SecretBinary"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Name == "" {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.SecretBinary)
	if err != nil {
		http.Error(w, "SecretBinary", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[req.Name] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:us-east-1:111111111111:secret:` + req.Name + `","Name":"` + req.Name + `"}`))
}

func (f *awsSecretsManagerSyncFixture) value(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name]
}

type gcpSecretManagerSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newGCPSecretManagerSyncFixture(t *testing.T) *gcpSecretManagerSyncFixture {
	t.Helper()
	f := &gcpSecretManagerSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *gcpSecretManagerSyncFixture) URL() string          { return f.server.URL }
func (f *gcpSecretManagerSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *gcpSecretManagerSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer gcp-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] != "projects" || parts[3] != "secrets" || !strings.HasSuffix(parts[4], ":addVersion") {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Payload.Data)
	if err != nil {
		http.Error(w, "payload.data", http.StatusBadRequest)
		return
	}
	key := strings.TrimSuffix(parts[4], ":addVersion")
	f.mu.Lock()
	f.values[parts[2]+"/"+key] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"name":"projects/` + parts[2] + `/secrets/` + key + `/versions/1"}`))
}

func (f *gcpSecretManagerSyncFixture) value(project, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[project+"/"+name]
}

type azureKeyVaultSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newAzureKeyVaultSyncFixture(t *testing.T) *azureKeyVaultSyncFixture {
	t.Helper()
	f := &azureKeyVaultSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *azureKeyVaultSyncFixture) URL() string          { return f.server.URL }
func (f *azureKeyVaultSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *azureKeyVaultSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer azure-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "secrets" || r.URL.Query().Get("api-version") == "" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		http.Error(w, "value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[parts[1]] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"id":"https://vault.example/secrets/` + parts[1] + `"}`))
}

func (f *azureKeyVaultSyncFixture) value(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name]
}

func servedAzureKeyVaultSecretDouble(secrets map[string]string, tags map[string]map[string]string, seen *[]string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+strings.Trim(r.URL.Path, "/"))
		if got := r.Header.Get("Authorization"); got != "Bearer azure-token" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "secrets":
			items := make([]map[string]any, 0, len(secrets))
			for name := range secrets {
				items = append(items, map[string]any{
					"id":   srv.URL + "/secrets/" + name,
					"tags": tags[name],
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": items})
		case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "secrets":
			value, ok := secrets[parts[1]]
			if !ok {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          srv.URL + "/secrets/" + parts[1],
				"value":       value,
				"contentType": "text/plain",
			})
		default:
			http.Error(w, "unexpected Azure Key Vault operation", http.StatusBadRequest)
		}
	}))
	return srv
}

type gitLabCISyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newGitLabCISyncFixture(t *testing.T) *gitLabCISyncFixture {
	t.Helper()
	f := &gitLabCISyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *gitLabCISyncFixture) URL() string          { return f.server.URL }
func (f *gitLabCISyncFixture) Client() *http.Client { return f.server.Client() }

func (f *gitLabCISyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("PRIVATE-TOKEN"); got != "gitlab-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "v4" || parts[2] != "projects" || parts[4] != "variables" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		http.Error(w, "value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[parts[3]+"/"+parts[5]] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"key":"` + parts[5] + `"}`))
}

func (f *gitLabCISyncFixture) value(project, key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[project+"/"+key]
}

type vercelSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newVercelSyncFixture(t *testing.T) *vercelSyncFixture {
	t.Helper()
	f := &vercelSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *vercelSyncFixture) URL() string          { return f.server.URL }
func (f *vercelSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *vercelSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer vercel-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "v10" || parts[1] != "projects" || parts[3] != "env" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Key == "" {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		http.Error(w, "value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[parts[2]+"/"+req.Key] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"key":"` + req.Key + `"}`))
}

func (f *vercelSyncFixture) value(project, key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[project+"/"+key]
}

type ciSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newCISyncFixture(t *testing.T) *ciSyncFixture {
	t.Helper()
	f := &ciSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *ciSyncFixture) URL() string          { return f.server.URL }
func (f *ciSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *ciSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer ci-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	if strings.Trim(r.URL.Path, "/") != "secrets" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Provider     string `json:"provider"`
		Key          string `json:"key"`
		EncodedValue string `json:"encoded_value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Provider == "" || req.Key == "" {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.EncodedValue)
	if err != nil {
		http.Error(w, "encoded_value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[req.Provider+"/"+req.Key] = string(decoded)
	f.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (f *ciSyncFixture) value(provider, key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[provider+"/"+key]
}

type kubernetesSecretSyncFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	values map[string]string
}

func newKubernetesSecretSyncFixture(t *testing.T) *kubernetesSecretSyncFixture {
	t.Helper()
	f := &kubernetesSecretSyncFixture{values: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *kubernetesSecretSyncFixture) URL() string          { return f.server.URL }
func (f *kubernetesSecretSyncFixture) Client() *http.Client { return f.server.Client() }

func (f *kubernetesSecretSyncFixture) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer k8s-token" {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "namespaces" || parts[4] != "secrets" {
		http.Error(w, "path", http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Data == nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(req.Data["value"])
	if err != nil {
		http.Error(w, "data.value", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.values[parts[3]+"/"+parts[5]] = string(decoded)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"kind":"Secret","apiVersion":"v1"}`))
}

func (f *kubernetesSecretSyncFixture) value(namespace, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[namespace+"/"+name]
}

var _ = context.Background
