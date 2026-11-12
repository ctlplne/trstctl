// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secretscan"
)

// OD-3: native GitLab and Bitbucket push hooks start repository secret
// scans the way GitHub's do. A GitLab hook proves a delivery with its signing
// token (webhook-signature over webhook-id, webhook-timestamp and the body,
// refused when stale) or its secret token (X-Gitlab-Token); a Bitbucket hook
// with its signature (X-Hub-Signature over the body). A wrong, missing or
// stale proof is refused, audited, and queues nothing; a redelivery queues
// nothing new; a push to a branch that is not the default one scans that
// branch's commit; a Bitbucket Cloud push of two branches and a deletion
// scans both branches; a Data Center refs_changed push scans its branch; a
// ref that could read as a git option is refused.
func TestServedGitLabAndBitbucketSecretScanHooksOD3(t *testing.T) {
	scanned := make(chan string, 16)
	fake := &fakeSecretRepoScanner{called: make(chan string, 16), report: secretscan.Report{
		Scanner: "gitleaks", EngineVersion: secretscan.GitleaksPinnedVersion, RulesActive: secretscan.GitleaksDefaultRulesActive,
	}, inspect: func(path string) {
		body, err := os.ReadFile(filepath.Join(path, "BRANCH")) // #nosec G304 -- the server's own temporary clone (CWE-22)
		if err != nil {
			scanned <- "unreadable: " + err.Error()
			return
		}
		scanned <- strings.TrimSpace(string(body))
	}}
	signingKey := []byte("od3-served-signing-key-32-bytes!")
	const glShared, bbShared = "od3-gitlab-shared-value", "od3-bitbucket-shared-value"
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.SecretScanner = fake
		d.SecretScanWebhooks = []config.SecretScanWebhook{
			{ID: "gl-token", TenantID: servedTestTenant, Provider: "gitlab", SecretRef: writeServedCredentialFile(t, "od3-gl-token", glShared)},
			{ID: "gl-signed", TenantID: servedTestTenant, Provider: "gitlab",
				SecretRef: writeServedCredentialFile(t, "od3-gl-signed", "whsec_"+base64.StdEncoding.EncodeToString(signingKey))},
			{ID: "bb", TenantID: servedTestTenant, Provider: "bitbucket", SecretRef: writeServedCredentialFile(t, "od3-bb", bbShared)},
		}
	})

	// The pushed repository: main and feature, each naming itself in BRANCH.
	// Its path ends in .git, which Bitbucket Cloud's html link plus ".git"
	// names (the lab cannot reach the providers; a public https clone URL
	// takes the same path).
	origin := filepath.Join(t.TempDir(), "payments.git")
	gitRun := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", origin}, args...)...).CombinedOutput() // #nosec G204 -- the local git over the test's own repository (CWE-78)
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(origin, 0o700); err != nil {
		t.Fatal(err)
	}
	gitRun("init", "-q", "-b", "main")
	gitRun("config", "user.email", "od3@example.test")
	gitRun("config", "user.name", "od3")
	commit := func(branch string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(origin, "BRANCH"), []byte(branch+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitRun("add", "BRANCH")
		gitRun("commit", "-q", "-m", branch)
		return gitRun("rev-parse", "HEAD")
	}
	mainSHA := commit("main")
	gitRun("checkout", "-q", "-b", "feature")
	featureSHA := commit("feature")
	gitRun("checkout", "-q", "main")

	deliver := func(hook string, headers map[string]string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/scans/hooks/"+hook, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	runs := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM discovery_runs WHERE tenant_id = $1`, h.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	finish := func(runID string) {
		t.Helper()
		deadline := time.After(repositoryScanWait)
		for {
			h.srv.dispatchOnce(context.Background())
			var status, message string
			if err := h.store.SystemPool().QueryRow(t.Context(),
				`SELECT status, error FROM discovery_runs WHERE tenant_id = $1 AND id = $2`, h.tenant, runID).Scan(&status, &message); err != nil {
				t.Fatal(err)
			}
			if status == "succeeded" {
				return
			}
			if status == "failed" {
				t.Fatalf("run %s failed: %s", runID, message)
			}
			select {
			case <-deadline:
				t.Fatalf("run %s is still %s", runID, status)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	scannedBranch := func() string {
		t.Helper()
		select {
		case got := <-scanned:
			return got
		case <-time.After(repositoryScanWait):
			t.Fatal("the scan never reached the scanner")
			return ""
		}
	}
	type receipt struct {
		RunID string `json:"run_id"`
		Runs  []struct {
			Ref   string `json:"ref"`
			RunID string `json:"run_id"`
		} `json:"runs"`
		Ignored string `json:"ignored"`
		Pong    bool   `json:"pong"`
	}
	read := func(status int, body []byte, want int) receipt {
		t.Helper()
		var r receipt
		if status != want || json.Unmarshal(body, &r) != nil {
			t.Fatalf("HTTP %d %s, want %d", status, body, want)
		}
		return r
	}

	// GitLab with a secret token: a push to feature, not the default branch.
	glPush := []byte(`{"object_kind":"push","event_name":"push","ref":"refs/heads/feature","before":"` + mainSHA + `","after":"` + featureSHA +
		`","checkout_sha":"` + featureSHA + `","project":{"path_with_namespace":"acme/payments","git_http_url":"` + origin + `"}}`)
	glHeaders := func(key, token string) map[string]string {
		headers := map[string]string{"X-Gitlab-Event": "Push Hook", "Idempotency-Key": key, "X-Gitlab-Event-UUID": key + "-uuid"}
		if token != "" {
			headers["X-Gitlab-Token"] = token
		}
		return headers
	}
	if status, body := deliver("gl-token", glHeaders("gl-1", ""), glPush); status != http.StatusUnauthorized {
		t.Fatalf("GitLab push without its token: HTTP %d %s", status, body)
	}
	if status, body := deliver("gl-token", glHeaders("gl-2", "od3-gitlab-shared-valuf"), glPush); status != http.StatusUnauthorized {
		t.Fatalf("GitLab push with a wrong token: HTTP %d %s", status, body)
	}
	if n := runs(); n != 0 {
		t.Fatalf("refused deliveries queued %d scans", n)
	}
	status, body := deliver("gl-token", glHeaders("gl-3", glShared), glPush)
	first := read(status, body, http.StatusAccepted)
	finish(first.RunID)
	if got := scannedBranch(); got != "feature" {
		t.Fatalf("the GitLab push to feature scanned %q", got)
	}
	status, body = deliver("gl-token", glHeaders("gl-3", glShared), glPush)
	if again := read(status, body, http.StatusAccepted); again.RunID != first.RunID || runs() != 1 {
		t.Fatalf("a GitLab redelivery queued again: %s (runs %d)", body, runs())
	}
	deleted := []byte(`{"object_kind":"push","ref":"refs/heads/feature","after":"0000000000000000000000000000000000000000","checkout_sha":null,` +
		`"project":{"path_with_namespace":"acme/payments","git_http_url":"` + origin + `"}}`)
	status, body = deliver("gl-token", glHeaders("gl-4", glShared), deleted)
	if r := read(status, body, http.StatusAccepted); r.Ignored == "" || runs() != 1 {
		t.Fatalf("a deleted GitLab branch: %s (runs %d)", body, runs())
	}
	mr := glHeaders("gl-5", glShared)
	mr["X-Gitlab-Event"] = "Merge Request Hook"
	status, body = deliver("gl-token", mr, []byte(`{"object_kind":"merge_request"}`))
	if r := read(status, body, http.StatusAccepted); r.Ignored != "Merge Request Hook" || runs() != 1 {
		t.Fatalf("a GitLab merge request event: %s (runs %d)", body, runs())
	}

	// GitLab with a signing token (Standard Webhooks).
	glMain := []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"` + mainSHA + `","checkout_sha":"` + mainSHA +
		`","project":{"path_with_namespace":"acme/payments","git_http_url":"` + origin + `"}}`)
	signed := func(id string, at time.Time, key []byte) map[string]string {
		stamp := strconv.FormatInt(at.Unix(), 10)
		mac := crypto.HMACSHA256(key, append([]byte(id+"."+stamp+"."), glMain...))
		return map[string]string{"X-Gitlab-Event": "Push Hook", "webhook-id": id, "webhook-timestamp": stamp,
			"webhook-signature": "v1," + base64.StdEncoding.EncodeToString(mac)}
	}
	if status, body := deliver("gl-signed", signed("msg_od3_stale", time.Now().Add(-10*time.Minute), signingKey), glMain); status != http.StatusUnauthorized {
		t.Fatalf("a stale signed GitLab delivery: HTTP %d %s", status, body)
	}
	if status, body := deliver("gl-signed", signed("msg_od3_wrong", time.Now(), []byte("not the signing key")), glMain); status != http.StatusUnauthorized {
		t.Fatalf("a GitLab delivery signed with another key: HTTP %d %s", status, body)
	}
	status, body = deliver("gl-signed", signed("msg_od3_1", time.Now(), signingKey), glMain)
	finish(read(status, body, http.StatusAccepted).RunID)
	if got := scannedBranch(); got != "main" {
		t.Fatalf("the signed GitLab push to main scanned %q", got)
	}

	// Bitbucket Cloud: one push of main and feature, and a deleted branch.
	bbSign := func(body []byte) string {
		return "sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte(bbShared), body))
	}
	cloud := []byte(`{"push":{"changes":[` +
		`{"new":{"type":"branch","name":"main","target":{"hash":"` + mainSHA + `"}}},` +
		`{"new":{"type":"branch","name":"feature","target":{"hash":"` + featureSHA + `"}}},` +
		`{"new":null,"old":{"type":"branch","name":"gone","target":{"hash":"` + mainSHA + `"}}}]},` +
		`"repository":{"full_name":"acme/payments","links":{"html":{"href":"` + strings.TrimSuffix(origin, ".git") + `"}}}}`)
	if status, body := deliver("bb", map[string]string{"X-Event-Key": "repo:push", "X-Request-UUID": "bb-0", "X-Hub-Signature": "sha256=" + strings.Repeat("0", 64)}, cloud); status != http.StatusUnauthorized {
		t.Fatalf("a Bitbucket push with a wrong signature: HTTP %d %s", status, body)
	}
	before := runs()
	status, body = deliver("bb", map[string]string{"X-Event-Key": "repo:push", "X-Request-UUID": "bb-1", "X-Hub-Signature": bbSign(cloud)}, cloud)
	pushed := read(status, body, http.StatusAccepted)
	if len(pushed.Runs) != 2 || pushed.Runs[0].Ref != "refs/heads/main" || pushed.Runs[1].Ref != "refs/heads/feature" || runs() != before+2 {
		t.Fatalf("a Bitbucket Cloud push of two branches: %s (runs %d → %d)", body, before, runs())
	}
	var branches []string
	for _, run := range pushed.Runs {
		finish(run.RunID)
		branches = append(branches, scannedBranch())
	}
	slices.Sort(branches)
	if strings.Join(branches, ",") != "feature,main" {
		t.Fatalf("the Bitbucket Cloud push scanned %v", branches)
	}

	// Bitbucket Data Center: refs_changed for feature, its http clone link.
	dc := []byte(`{"eventKey":"repo:refs_changed","repository":{"slug":"payments","project":{"key":"ACME"},` +
		`"links":{"clone":[{"href":"ssh://git@bitbucket.example.test:7999/acme/payments.git","name":"ssh"},{"href":"` + origin + `","name":"http"}]}},` +
		`"changes":[{"ref":{"id":"refs/heads/feature","displayId":"feature","type":"BRANCH"},"fromHash":"` + mainSHA + `","toHash":"` + featureSHA + `","type":"UPDATE"}]}`)
	status, body = deliver("bb", map[string]string{"X-Event-Key": "repo:refs_changed", "X-Request-Id": "bb-dc-1", "X-Hub-Signature": bbSign(dc)}, dc)
	finish(read(status, body, http.StatusAccepted).RunID)
	if got := scannedBranch(); got != "feature" {
		t.Fatalf("the Data Center push to feature scanned %q", got)
	}
	ping := []byte(`{"test":true}`)
	status, body = deliver("bb", map[string]string{"X-Event-Key": "diagnostics:ping", "X-Request-Id": "bb-ping", "X-Hub-Signature": bbSign(ping)}, ping)
	if r := read(status, body, http.StatusOK); !r.Pong {
		t.Fatalf("a Bitbucket ping: %s", body)
	}

	// A ref that git could read as an option is refused and scans nothing.
	evil := []byte(`{"push":{"changes":[{"new":{"type":"branch","name":"--upload-pack=touch od3-pwned","target":{"hash":"` + mainSHA + `"}}}]},` +
		`"repository":{"full_name":"acme/payments","links":{"html":{"href":"` + strings.TrimSuffix(origin, ".git") + `"}}}}`)
	before = runs()
	if status, body := deliver("bb", map[string]string{"X-Event-Key": "repo:push", "X-Request-UUID": "bb-evil", "X-Hub-Signature": bbSign(evil)}, evil); status != http.StatusBadRequest || runs() != before {
		t.Fatalf("an option-shaped ref: HTTP %d %s (runs %d → %d)", status, body, before, runs())
	}

	// Each refused delivery is audited with its hook and why.
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "od3-hook-auditor", "audit:read")
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/audit/events?type=secret.scan_hook.refused&limit=20", auditor, nil)
	var refused struct {
		Events []struct {
			Data struct {
				HookID string `json:"hook_id"`
				Reason string `json:"reason"`
			} `json:"data"`
		} `json:"events"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &refused) != nil {
		t.Fatalf("refused deliveries in the audit record = %d %s", status, raw)
	}
	reasons := map[string]int{}
	for _, ev := range refused.Events {
		reasons[ev.Data.HookID+"/"+ev.Data.Reason]++
	}
	for key, n := range map[string]int{
		"gl-token/signature_missing": 1, "gl-token/signature_mismatch": 1,
		"gl-signed/signature_stale": 1, "gl-signed/signature_mismatch": 1, "bb/signature_mismatch": 1,
	} {
		if reasons[key] != n {
			t.Fatalf("refused deliveries = %v, want %s × %d", reasons, key, n)
		}
	}
}
