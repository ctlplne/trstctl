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
