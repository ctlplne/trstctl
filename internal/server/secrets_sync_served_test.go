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
