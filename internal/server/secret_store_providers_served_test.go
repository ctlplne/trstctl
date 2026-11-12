// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// A173 Done-when: code-host secret stores beside the four cloud secret
// managers. One served secret_store source reads GitHub Actions secrets
// (repository, environment and organization; metadata only, because GitHub
// never returns a value) and GitLab CI/CD variables (project and group; a
// hidden variable is flagged as not inspectable). With content inspection, a
// certificate and an API key in GitLab variables become findings and no
// value is kept; asking to inspect GitHub secrets fails that provider with
// the reason; a provider outside the set is refused with the specific
// unsupported error; and the source catalog lists six secret-store providers.
func TestServedSecretStoreProvidersBeyondCloudSecretManagers(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("ci.a173.example", "ci.a173.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	gitlabToken := "gl" + "pat-" + strings.Repeat("A173srv", 4)[:24]
	raw := []string{gitlabToken}

	github := secretstoretest.NewGitHub("gh-token", "acme", "api", "acme-org", []secretstoretest.GitHubSecret{
		{Scope: "repo", Name: "DEPLOY_KEY"}, {Scope: "env:production", Name: "PROD_DB_URL"}, {Scope: "org", Name: "ORG_PAT", Visibility: "all"},
	})
	t.Cleanup(github.Close)
	gitlab := secretstoretest.NewGitLab("gl-token", []secretstoretest.GitLabVariable{
		{Scope: "project:acme/api", Key: "DEPLOY_TOKEN", Value: gitlabToken, Masked: true},
		{Scope: "project:acme/api", Key: "TLS_CERT", Value: certPEM, VariableType: "file"},
		{Scope: "project:acme/api", Key: "SIGNING_KEY", Value: "never-returned", Hidden: true},
		{Scope: "group:acme", Key: "REGION", Value: "us-east-1"},
	})
	t.Cleanup(gitlab.Close)
	for env, value := range map[string]string{"TRSTCTL_A173_GH": "gh-token", "TRSTCTL_A173_GL": "gl-token"} {
		t.Setenv(env, value)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A173_GH", "env:TRSTCTL_A173_GL"))
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))

	at := func(url string, fields map[string]any) map[string]any {
		fields["endpoint"], fields["allow_private_endpoint"], fields["private_egress_cidrs"] = url, true, []string{serviceNowSinkCIDR(t, url)}
		return fields
	}
	type runResult struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		Error         string `json:"error"`
		TargetResults []struct {
			Target string `json:"target"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"target_results"`
	}
	runSource := func(name string, providers ...map[string]any) (string, runResult) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
			"name": name, "kind": "secret_store", "config": map[string]any{"providers": providers}})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
			t.Fatalf("create %s: %d %s", name, status, body)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
		var run runResult
		if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
			t.Fatalf("run %s: %d %s", name, status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatalf("drain %s: %v", name, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+run.ID, tok, nil)
		if status != http.StatusOK || json.Unmarshal(body, &run) != nil {
			t.Fatalf("read run %s: %d %s", name, status, body)
		}
		return source.ID, run
	}
	type findingRow struct {
		SourceID string         `json:"source_id"`
		Kind     string         `json:"kind"`
		Metadata map[string]any `json:"metadata"`
	}
	findings := func(sourceID string) ([]findingRow, []byte) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?source_kind=secret_store&limit=100", tok, nil)
		var list struct {
			Items []findingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings: %d %s", status, body)
		}
		var out []findingRow
		for _, f := range list.Items {
			if f.SourceID == sourceID {
				out = append(out, f)
			}
		}
		return out, body
	}

	sourceID, run := runSource("code-hosts-and-stores",
		at(github.URL(), map[string]any{"provider": "github-actions", "owner": "acme", "repo": "api", "environments": []string{"production"}, // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			"org": "acme-org", "token_ref": "env:TRSTCTL_A173_GH"}),
		at(gitlab.URL(), map[string]any{"provider": "gitlab-ci", "project": "acme/api", "group": "acme", "token_ref": "env:TRSTCTL_A173_GL", "inspect_content": true}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
	)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("run = %+v", run)
	}
	rows, body := findings(sourceID)
	got := map[string]int{}
	var hiddenReason string
	for _, f := range rows {
		provider, _ := f.Metadata["provider"].(string)
		got[provider+"/"+f.Kind]++
		if f.Metadata["secret_name"] == "SIGNING_KEY" && f.Kind == "cloud_secret_resource" {
			hiddenReason, _ = f.Metadata["content_unavailable_reason"].(string)
		}
	}
	want := map[string]int{
		"github-actions/cloud_secret_resource": 3,
		"gitlab-ci/cloud_secret_resource":      4,
		"gitlab-ci/x509_certificate":           1,
		"gitlab-ci/secret_store_api_key":       1,
	}
	for key, n := range want {
		if got[key] != n {
			t.Fatalf("%s = %d, want %d (all: %v)", key, got[key], n, got)
		}
	}
	if !strings.Contains(hiddenReason, "hidden") {
		t.Fatalf("hidden GitLab variable reason = %q", hiddenReason)
	}
	for _, value := range raw {
		if strings.Contains(string(body), value) {
			t.Fatal("the findings response carries a stored value")
		}
	}
	for _, call := range github.Seen() {
		if !strings.Contains(call, "/secrets?per_page=") {
			t.Fatalf("unexpected GitHub call %s", call)
		}
	}

	// GitHub secret values cannot be inspected; the provider fails with the
	// reason and the rest of the source still runs.
	_, run = runSource("github-inspect-refused",
		at(github.URL(), map[string]any{"provider": "github-actions", "owner": "acme", "repo": "api", "token_ref": "env:TRSTCTL_A173_GH", "inspect_content": true}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		at(gitlab.URL(), map[string]any{"provider": "gitlab-ci", "group": "acme", "token_ref": "env:TRSTCTL_A173_GL"}),                                              // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
	)
	outcomes := map[string]string{}
	for _, r := range run.TargetResults {
		outcomes[r.Target] = r.Status + ": " + r.Error
	}
	if run.Status != "partial" || !strings.Contains(outcomes["github-actions"], "never returns Actions secret values") || !strings.HasPrefix(outcomes["gitlab-ci"], "succeeded") {
		t.Fatalf("run = %s / %+v", run.Status, outcomes)
	}
	// A provider outside the served set is refused when the source is
	// created, naming it.
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "unserved-store", "kind": "secret_store", "config": map[string]any{"providers": []map[string]any{{"provider": "unlisted-store"}}}})
	if status != http.StatusBadRequest || !strings.Contains(string(body), `unsupported provider \"unlisted-store\"`) {
		t.Fatalf("unserved provider = %d %s", status, body)
	}
	// The source catalog lists the served secret-store providers: the six of
	// A173, the four of OD-13 and the two of OD-14.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/capabilities", tok, nil)
	var catalog struct {
		Items []struct {
			Kind      string `json:"kind"`
			Providers []struct {
				ID string `json:"id"`
			} `json:"providers"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil {
		t.Fatalf("catalog = %d %s", status, body)
	}
	var ids []string
	for _, item := range catalog.Items {
		if item.Kind == "secret_store" {
			for _, p := range item.Providers {
				ids = append(ids, p.ID)
			}
		}
	}
	if strings.Join(ids, ",") != servedSecretStoreProviders {
		t.Fatalf("secret_store providers = %v, want the served ones", ids)
	}
}
