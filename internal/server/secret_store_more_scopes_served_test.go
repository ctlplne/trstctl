// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// OD-2 Done-when: GitHub's Dependabot and Codespaces secrets and GitLab's
// instance-level variables join the code-host secret stores. One served
// secret_store source lists a repository's and an organization's Actions,
// Dependabot and Codespaces secrets and the token owner's own Codespaces
// secrets (metadata only, each naming its store), and a GitLab instance's
// variables with an administrator's token (values wiped; with content
// inspection an API key among them becomes a finding and no value is
// kept). An unknown GitHub store fails that provider naming it, a
// maintainer's token listing instance variables fails naming the 403 and
// why, and the source catalog offers the new fields.
func TestServedGitHubDependabotCodespacesAndGitLabInstanceVariablesOD2(t *testing.T) {
	gitlabToken := "gl" + "pat-" + strings.Repeat("OD2srvInst", 3)[:24]
	github := secretstoretest.NewGitHub("gh-token", "acme", "api", "acme-org", []secretstoretest.GitHubSecret{
		{Scope: "repo", Name: "DEPLOY_KEY"},
		{Scope: "repo", Type: "dependabot", Name: "NPM_REGISTRY_PAT"},
		{Scope: "repo", Type: "codespaces", Name: "DEV_DB_URL"},
		{Scope: "org", Type: "dependabot", Name: "ORG_PACKAGES_PAT", Visibility: "selected"},
		{Scope: "org", Type: "codespaces", Name: "ORG_SANDBOX_PAT", Visibility: "all"},
		{Scope: "user", Type: "codespaces", Name: "MY_PAT", Visibility: "private"},
	})
	t.Cleanup(github.Close)
	gitlab := secretstoretest.NewGitLabWithAdmin("gl-maintainer", "gl-admin", []secretstoretest.GitLabVariable{
		{Scope: "instance", Key: "INSTANCE_DEPLOY_PAT", Value: gitlabToken, Masked: true},
		{Scope: "instance", Key: "REGION", Value: "us-east-1"},
		{Scope: "group:acme", Key: "GROUP_VAR", Value: "x"},
	})
	t.Cleanup(gitlab.Close)
	for env, value := range map[string]string{"TRSTCTL_OD2_GH": "gh-token", "TRSTCTL_OD2_GL_ADMIN": "gl-admin", "TRSTCTL_OD2_GL": "gl-maintainer"} {
		t.Setenv(env, value)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_OD2_GH", "env:TRSTCTL_OD2_GL_ADMIN", "env:TRSTCTL_OD2_GL"))
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

	sourceID, run := runSource("od2-code-host-stores",
		at(github.URL(), map[string]any{"provider": "github-actions", "owner": "acme", "repo": "api", "org": "acme-org", // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			"stores": []string{"actions", "dependabot", "codespaces"}, "user_codespaces": true, "token_ref": "env:TRSTCTL_OD2_GH"}),
		at(gitlab.URL(), map[string]any{"provider": "gitlab-ci", "instance": true, "token_ref": "env:TRSTCTL_OD2_GL_ADMIN", "inspect_content": true}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
	)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("run = %+v", run)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?source_kind=secret_store&limit=100", tok, nil)
	var list struct {
		Items []struct {
			SourceID string         `json:"source_id"`
			Kind     string         `json:"kind"`
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("findings: %d %s", status, body)
	}
	if strings.Contains(string(body), gitlabToken) || strings.Contains(string(body), "us-east-1") {
		t.Fatal("the findings response carries a stored value")
	}
	stores := map[string]string{}
	kinds := map[string]int{}
	for _, f := range list.Items {
		if f.SourceID != sourceID {
			continue
		}
		provider, _ := f.Metadata["provider"].(string)
		kinds[provider+"/"+f.Kind]++
		if f.Kind != "cloud_secret_resource" {
			continue
		}
		name, _ := f.Metadata["secret_name"].(string)
		store, _ := f.Metadata["store"].(string)
		scope, _ := f.Metadata["scope"].(string)
		stores[name] = provider + " " + store + "/" + scope
	}
	for key, n := range map[string]int{
		"github-actions/cloud_secret_resource": 6,
		"gitlab-ci/cloud_secret_resource":      2,
		"gitlab-ci/secret_store_api_key":       1,
	} {
		if kinds[key] != n {
			t.Fatalf("%s = %d, want %d (all: %v)", key, kinds[key], n, kinds)
		}
	}
	for name, want := range map[string]string{
		"DEPLOY_KEY":          "github-actions actions/repository",
		"NPM_REGISTRY_PAT":    "github-actions dependabot/repository",
		"DEV_DB_URL":          "github-actions codespaces/repository",
		"ORG_PACKAGES_PAT":    "github-actions dependabot/organization",
		"ORG_SANDBOX_PAT":     "github-actions codespaces/organization",
		"MY_PAT":              "github-actions codespaces/user",
		"INSTANCE_DEPLOY_PAT": "gitlab-ci /instance",
		"REGION":              "gitlab-ci /instance",
	} {
		if stores[name] != want {
			t.Fatalf("%s = %q, want %q (all: %v)", name, stores[name], want, stores)
		}
	}
	for _, call := range github.Seen() {
		if call != "GET /user" && !strings.Contains(call, "/secrets?per_page=") {
			t.Fatalf("unexpected GitHub call %s", call)
		}
	}

	// An unknown GitHub store fails that provider naming it; a maintainer's
	// token cannot list instance variables, and the failure says why.
	_, run = runSource("od2-refusals",
		at(github.URL(), map[string]any{"provider": "github-actions", "owner": "acme", "repo": "api", "stores": []string{"packages"}, "token_ref": "env:TRSTCTL_OD2_GH"}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		at(gitlab.URL(), map[string]any{"provider": "gitlab-ci", "group": "acme", "instance": true, "token_ref": "env:TRSTCTL_OD2_GL"}),                                   // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
	)
	outcomes := map[string]string{}
	for _, r := range run.TargetResults {
		outcomes[r.Target] = r.Status + ": " + r.Error
	}
	if run.Status != "failed" || !strings.Contains(outcomes["github-actions"], `unknown secret store "packages"`) ||
		!strings.Contains(outcomes["gitlab-ci"], "administrator") || !strings.Contains(outcomes["gitlab-ci"], "403") {
		t.Fatalf("refusals = %s / %+v", run.Status, outcomes)
	}

	// The source catalog offers the new fields for the secret stores.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/capabilities", tok, nil)
	var catalog struct {
		Items []struct {
			Kind          string `json:"kind"`
			Configuration []struct {
				Path string `json:"path"`
			} `json:"configuration"`
			Providers []struct {
				ID     string   `json:"id"`
				Label  string   `json:"label"`
				Fields []string `json:"fields"`
			} `json:"providers"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil {
		t.Fatalf("catalog = %d %s", status, body)
	}
	for _, item := range catalog.Items {
		if item.Kind != "secret_store" {
			continue
		}
		var paths []string
		for _, f := range item.Configuration {
			paths = append(paths, f.Path)
		}
		for _, path := range []string{"providers[].stores", "providers[].user_codespaces", "providers[].instance"} {
			if !slices.Contains(paths, path) {
				t.Fatalf("secret_store configuration lacks %s: %v", path, paths)
			}
		}
		for _, p := range item.Providers {
			switch p.ID {
			case "github-actions":
				if !strings.Contains(p.Label, "Dependabot") || !slices.Contains(p.Fields, "stores") || !slices.Contains(p.Fields, "user_codespaces") {
					t.Fatalf("github-actions provider = %+v", p)
				}
			case "gitlab-ci":
				if !slices.Contains(p.Fields, "instance") {
					t.Fatalf("gitlab-ci provider = %+v", p)
				}
			}
		}
		return
	}
	t.Fatal("the catalog has no secret_store item")
}
