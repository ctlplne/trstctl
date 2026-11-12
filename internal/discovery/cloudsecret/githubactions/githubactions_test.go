// SPDX-License-Identifier: BUSL-1.1

package githubactions_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/githubactions"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

func TestGitHubActionsInventoriesRepositoryEnvironmentAndOrgSecrets(t *testing.T) {
	secrets := []secretstoretest.GitHubSecret{
		{Scope: "repo", Name: "DEPLOY_KEY"}, {Scope: "repo", Name: "NPM_TOKEN"},
		{Scope: "env:production", Name: "PROD_DB_URL"}, {Scope: "org", Name: "ORG_PAT", Visibility: "private"},
	}
	for i := 0; i < 130; i++ {
		secrets = append(secrets, secretstoretest.GitHubSecret{Scope: "repo", Name: fmt.Sprintf("BULK_%03d", i)})
	}
	stand := secretstoretest.NewGitHub("gh-a173", "acme", "api", "acme-org", secrets)
	t.Cleanup(stand.Close)
	e, err := githubactions.New(githubactions.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Owner: "acme", Repo: "api", Environments: []string{"production"},
		Org: "acme-org", Token: cloudcert.StaticToken("gh-a173")})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 134 {
		t.Fatalf("found %d secrets, want 134 across two pages", len(found))
	}
	byName := map[string]map[string]string{}
	for _, f := range found {
		if f.Provider != githubactions.ProviderName || f.Metadata["value_readable"] != "false" || f.Metadata["content_inspected"] != "false" {
			t.Fatalf("finding = %+v", f)
		}
		byName[f.SecretName] = f.Metadata
	}
	if byName["PROD_DB_URL"]["scope"] != "environment" || byName["PROD_DB_URL"]["environment"] != "production" ||
		byName["ORG_PAT"]["scope"] != "organization" || byName["ORG_PAT"]["visibility"] != "private" ||
		byName["DEPLOY_KEY"]["repository"] != "acme/api" {
		t.Fatalf("scopes = %+v", byName)
	}
	for _, call := range stand.Seen() {
		if !strings.HasPrefix(call, "GET ") || !strings.Contains(call, "/secrets?per_page=100&page=") {
			t.Fatalf("unexpected call %s", call)
		}
	}
}

func TestGitHubActionsRefusesContentInspectionAndBadScopes(t *testing.T) {
	tok := cloudcert.StaticToken("x")
	if _, err := githubactions.New(githubactions.Config{Owner: "a", Repo: "b", Token: tok, InspectContent: true}); !errors.Is(err, githubactions.ErrNoContentInspection) {
		t.Fatalf("inspect_content = %v", err)
	}
	for name, cfg := range map[string]githubactions.Config{
		"no scope":         {Token: tok},
		"owner only":       {Owner: "a", Token: tok},
		"env without repo": {Org: "o", Environments: []string{"prod"}, Token: tok},
		"no token":         {Owner: "a", Repo: "b"},
	} {
		if _, err := githubactions.New(cfg); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	stand := secretstoretest.NewGitHub("right", "a", "b", "", nil)
	t.Cleanup(stand.Close)
	e, err := githubactions.New(githubactions.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Owner: "a", Repo: "b", Token: cloudcert.StaticToken("wrong")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Enumerate(context.Background()); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("wrong token = %v", err)
	}
}

// OD-2: Dependabot and Codespaces secrets are listed beside Actions secrets
// for the repository and the org, and the token owner's own Codespaces
// secrets under their login; every finding names its store, nothing reads a
// value, and an unknown store or Actions-only environments without Actions
// are refused by name.
func TestGitHubDependabotAndCodespacesSecretsOD2(t *testing.T) {
	stand := secretstoretest.NewGitHub("gh-od2", "acme", "api", "acme-org", []secretstoretest.GitHubSecret{
		{Scope: "repo", Name: "DEPLOY_KEY"},
		{Scope: "repo", Type: "dependabot", Name: "NPM_REGISTRY_PAT"},
		{Scope: "repo", Type: "codespaces", Name: "DEV_DB_URL"},
		{Scope: "org", Type: "dependabot", Name: "ORG_PACKAGES_PAT", Visibility: "selected"},
		{Scope: "org", Type: "codespaces", Name: "ORG_SANDBOX_PAT", Visibility: "all"},
		{Scope: "user", Type: "codespaces", Name: "MY_PAT", Visibility: "private"},
		{Scope: "org", Name: "ORG_ACTIONS_ONLY"},
	})
	t.Cleanup(stand.Close)
	e, err := githubactions.New(githubactions.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Owner: "acme", Repo: "api", Org: "acme-org",
		Stores: []string{" Dependabot", "codespaces", "dependabot"}, UserCodespaces: true, Token: cloudcert.StaticToken("gh-od2")})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range found {
		if f.Provider != githubactions.ProviderName || f.Metadata["value_readable"] != "false" || f.Metadata["content_inspected"] != "false" {
			t.Fatalf("finding = %+v", f)
		}
		got[f.SecretName] = f.Metadata["store"] + "/" + f.Metadata["scope"] + " " + f.Metadata["resource_id"] + " " + f.Metadata["visibility"]
	}
	host := strings.TrimPrefix(stand.URL(), "http://")
	want := map[string]string{
		"NPM_REGISTRY_PAT": "dependabot/repository github://" + host + "/acme/api/dependabot/secrets/NPM_REGISTRY_PAT ",
		"DEV_DB_URL":       "codespaces/repository github://" + host + "/acme/api/codespaces/secrets/DEV_DB_URL ",
		"ORG_PACKAGES_PAT": "dependabot/organization github://" + host + "/acme-org/dependabot/secrets/ORG_PACKAGES_PAT selected",
		"ORG_SANDBOX_PAT":  "codespaces/organization github://" + host + "/acme-org/codespaces/secrets/ORG_SANDBOX_PAT all",
		"MY_PAT":           "codespaces/user github://" + host + "/users/" + secretstoretest.GitHubLogin + "/codespaces/secrets/MY_PAT private",
	}
	if len(got) != len(want) {
		t.Fatalf("found %v, want exactly %v (Actions secrets were not chosen)", got, want)
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("%s = %q, want %q", name, got[name], w)
		}
	}
	for _, call := range stand.Seen() {
		if call != "GET /user" && (!strings.HasPrefix(call, "GET ") || !strings.Contains(call, "/secrets?per_page=100&page=1") || strings.Contains(call, "/actions/")) {
			t.Fatalf("unexpected call %s", call)
		}
	}

	tok := cloudcert.StaticToken("x")
	for name, cfg := range map[string]githubactions.Config{
		"unknown store":            {Owner: "a", Repo: "b", Stores: []string{"packages"}, Token: tok},
		"environments, no actions": {Owner: "a", Repo: "b", Environments: []string{"prod"}, Stores: []string{"dependabot"}, Token: tok},
	} {
		if _, err := githubactions.New(cfg); err == nil {
			t.Fatalf("%s accepted", name)
		} else if name == "unknown store" && !strings.Contains(err.Error(), `"packages"`) {
			t.Fatalf("unknown store error = %v, want it named", err)
		}
	}
	// The token owner's Codespaces secrets alone are a scope.
	if _, err := githubactions.New(githubactions.Config{UserCodespaces: true, Token: tok}); err != nil {
		t.Fatalf("user Codespaces alone = %v", err)
	}
}
