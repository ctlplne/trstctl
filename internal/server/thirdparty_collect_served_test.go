// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// n6PushImage pushes a one-layer OCI image to a stock registry over the
// distribution API and returns its manifest digest.
func n6PushImage(t *testing.T, registry, repo, tag string, files map[string]string, env string) string {
	t.Helper()
	upload := func(data []byte) string {
		t.Helper()
		digest := "sha256:" + crypto.SHA256Hex(data)
		resp, err := http.Post(registry+"/v2/"+repo+"/blobs/uploads/", "application/octet-stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		location := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusAccepted || location == "" {
			t.Fatalf("start upload: HTTP %d", resp.StatusCode)
		}
		if !strings.HasPrefix(location, "http") {
			location = registry + location
		}
		sep := "?"
		if strings.Contains(location, "?") {
			sep = "&"
		}
		req, _ := http.NewRequest(http.MethodPut, location+sep+"digest="+digest, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		put, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = put.Body.Close()
		if put.StatusCode != http.StatusCreated {
			t.Fatalf("finish upload: HTTP %d", put.StatusCode)
		}
		return digest
	}
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"Env":["` + env + `"]},"rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest, layerDigest := upload(config), upload(layer.Bytes())
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": layer.Len()}}})
	req, _ := http.NewRequest(http.MethodPut, registry+"/v2/"+repo+"/manifests/"+tag, bytes.NewReader(manifest))
	req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push manifest: HTTP %d", resp.StatusCode)
	}
	return "sha256:" + crypto.SHA256Hex(manifest)
}

// N6: trstctl reads a third-party scan's content from the provider itself — an
// image from a stock registry, Slack channel history and Jira issues from
// stand-ins built from their API references — in the layout of each provider's
// export, so every finding names the object it sat in. The collected content
// never reaches an event, and the collection's directory is gone after the run.
func TestServedNativeLeakScanCollectionN6(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", "registry:2").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the registry:2 image is not present locally: %v\n%s", err, out)
	}
	_, address := a201Container(t, "5000", "registry:2")
	registry := "http://" + address
	a201Await(t, "the registry", func() bool {
		resp, err := http.Get(registry + "/v2/")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	imageDigest := n6PushImage(t, registry, "team/app", "v1",
		map[string]string{"app/.env": "DB_PASSWORD=LEAK-N6-registry-layer\n", "app/README": "nothing here\n"}, "API_KEY=LEAK-N6-registry-env")

	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/conversations.history" || r.Header.Get("Authorization") != "Bearer n6-slack-token" {
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"ok":true,"messages":[{"ts":"1762246800.000100","text":"deploying"},{"ts":"1762250400.000200","text":"try LEAK-N6-slack"}],"has_more":false}`)
	}))
	t.Cleanup(slack.Close)
	jira := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/search" || r.Header.Get("Authorization") != "Bearer n6-jira-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"total":2,"issues":[{"key":"OPS-6","fields":{"summary":"fine"}},{"key":"OPS-7","fields":{"summary":"rotate","description":"password LEAK-N6-jira"}}]}`)
	}))
	t.Cleanup(jira.Close)
	const ciSHA = "89abcdef0123456789abcdef0123456789abcdef"
	var runLogs bytes.Buffer
	zw := zip.NewWriter(&runLogs)
	entry, _ := zw.Create("deploy/3_Run deploy.txt")
	_, _ = entry.Write([]byte("step\nexport TOKEN=LEAK-N6-github\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ci := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/app/actions/runs" && r.Header.Get("Authorization") == "Bearer n6-github-token":
			_, _ = fmt.Fprintf(w, `{"workflow_runs":[{"id":4242,"head_sha":"%s"}]}`, ciSHA)
		case r.URL.Path == "/repos/acme/app/actions/runs/4242/logs" && r.Header.Get("Authorization") == "Bearer n6-github-token":
			http.Redirect(w, r, "/artifacts/run-4242.zip", http.StatusFound)
		case r.URL.Path == "/artifacts/run-4242.zip":
			_, _ = w.Write(runLogs.Bytes())
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fapp/jobs" && r.Header.Get("PRIVATE-TOKEN") == "n6-gitlab-token":
			_, _ = fmt.Fprintf(w, `[{"id":77,"created_at":"2026-11-04T08:00:00.000Z","commit":{"id":"%s"}}]`, ciSHA)
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fapp/jobs/77/trace" && r.Header.Get("PRIVATE-TOKEN") == "n6-gitlab-token":
			_, _ = fmt.Fprint(w, "$ make release\nexport TOKEN=LEAK-N6-gitlab\n")
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	t.Cleanup(ci.Close)

	t.Setenv("TRSTCTL_N6_SLACK", "n6-slack-token")
	t.Setenv("TRSTCTL_N6_JIRA", "n6-jira-token")
	t.Setenv("TRSTCTL_N6_WRONG", "not-the-token")
	t.Setenv("TRSTCTL_N6_GITHUB", "n6-github-token")
	t.Setenv("TRSTCTL_N6_GITLAB", "n6-gitlab-token")
	scanner := &a174MarkerScanner{marker: "LEAK-N6"}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		allowOutboundEnvCredentialRefs("env:TRSTCTL_N6_SLACK", "env:TRSTCTL_N6_JIRA", "env:TRSTCTL_N6_WRONG", "env:TRSTCTL_N6_GITHUB", "env:TRSTCTL_N6_GITLAB"),
		func(d *Deps) { d.SecretScanner = scanner })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "trstctl-collect-*"))

	ingest := func(provider, source string, collect map[string]any) string {
		t.Helper()
		collect["allow_private_endpoint"], collect["private_egress_cidrs"] = true, []string{"127.0.0.1/32"}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/"+provider+"/ingest", tok, "n6-"+source,
			map[string]any{"source": source, "event": "n6", "collect": collect})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("ingest %s: HTTP %d %s", source, status, body)
		}
		return receipt.RunID
	}
	runs := map[string]string{
		"registry": ingest("container_registry", "team-app", map[string]any{"base_url": registry, "repository": "team/app", "reference": "v1"}),
		"slack":    ingest("slack", "ops-slack", map[string]any{"base_url": slack.URL, "token_ref": "env:TRSTCTL_N6_SLACK", "channels": []string{"C0OPS"}}),                  // #nosec G101 -- env: references to test-only stand-in tokens, no credential values (CWE-798)
		"jira":     ingest("jira", "ops-jira", map[string]any{"base_url": jira.URL, "token_ref": "env:TRSTCTL_N6_JIRA", "jql": "project = OPS"}),                             // #nosec G101 -- env: references to test-only stand-in tokens, no credential values (CWE-798)
		"refused":  ingest("slack", "ops-slack-wrong", map[string]any{"base_url": slack.URL, "token_ref": "env:TRSTCTL_N6_WRONG", "channels": []string{"C0OPS"}}),            // #nosec G101 -- env: references to test-only stand-in tokens, no credential values (CWE-798)
		"github":   ingest("cicd_log", "acme-app-actions", map[string]any{"base_url": ci.URL, "token_ref": "env:TRSTCTL_N6_GITHUB", "system": "github", "repo": "acme/app"}), // #nosec G101 -- env: references to test-only stand-in tokens, no credential values (CWE-798)
		"gitlab":   ingest("cicd_log", "group-app-jobs", map[string]any{"base_url": ci.URL, "token_ref": "env:TRSTCTL_N6_GITLAB", "system": "gitlab", "repo": "group/app"}),  // #nosec G101 -- env: references to test-only stand-in tokens, no credential values (CWE-798)
	}
	type finding struct {
		Ref      string         `json:"ref"`
		Metadata map[string]any `json:"metadata"`
	}
	runStatus := func(runID string) (string, string) {
		var status, detail string
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status, coalesce(error, '') FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status, &detail)
		return status, detail
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		done := 0
		for _, runID := range runs {
			if status, _ := runStatus(runID); status == "succeeded" || status == "failed" {
				done++
			}
		}
		if done == len(runs) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("collections did not finish: %v", runs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	findings := func(name string) []finding {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runs[name], tok, nil)
		var list struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("%s findings: HTTP %d %s", name, status, body)
		}
		if strings.Contains(string(body), "LEAK-N6") {
			t.Fatalf("%s findings carry collected content: %s", name, body)
		}
		return list.Items
	}
	object := func(f finding) map[string]any {
		o, _ := f.Metadata["provider_object"].(map[string]any)
		return o
	}
	reg := findings("registry")
	if len(reg) != 2 {
		t.Fatalf("registry findings = %+v", reg)
	}
	for _, f := range reg {
		if o := object(f); o["repository"] != "team/app" || o["digest"] != imageDigest || f.Metadata["collection_truncated"] != false {
			t.Fatalf("registry finding = %+v", f)
		}
	}
	if s := findings("slack"); len(s) != 1 || object(s[0])["channel_id"] != "C0OPS" || object(s[0])["message_ts"] != "1762250400.000200" {
		t.Fatalf("slack findings = %+v", s)
	}
	if j := findings("jira"); len(j) != 1 || object(j[0])["issue_key"] != "OPS-7" {
		t.Fatalf("jira findings = %+v", j)
	}
	if g := findings("github"); len(g) != 1 || object(g[0])["system"] != "github" || object(g[0])["repo"] != "acme/app" ||
		object(g[0])["commit_sha"] != ciSHA || object(g[0])["run_id"] != "4242" {
		t.Fatalf("github findings = %+v", g)
	}
	if g := findings("gitlab"); len(g) != 1 || object(g[0])["system"] != "gitlab" || object(g[0])["repo"] != "group/app" || object(g[0])["job_id"] != "77" {
		t.Fatalf("gitlab findings = %+v", g)
	}
	if status, detail := runStatus(runs["refused"]); status != "failed" || !strings.Contains(detail, "native collection refused") {
		t.Fatalf("a collection with a refused token = %s %q", status, detail)
	}
	if len(findings("refused")) != 0 {
		t.Fatal("a refused collection recorded findings")
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "trstctl-collect-*"))
	if len(after) > len(before) {
		t.Fatalf("collection directories left behind: %v", after)
	}
	if h.logContains(t, "LEAK-N6") || h.logContains(t, "n6-slack-token") {
		t.Fatal("collected content or a collection token reached the event log")
	}
	t.Logf("N6_COLLECT_OK image=%s registry=%d slack=1 jira=1 github=1 gitlab=1", imageDigest, len(reg))
}
