// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// TestServedSecretProjectAndEnvironmentRenameA235L3 is A235-L3 over the
// served API and the CLI: access:write renames a project and one of its
// environments; the slugs stay, so the secrets under them keep their names,
// their values and their environment's restriction, and members keep their
// grants; a blank or over-long name is 400, an unknown project or
// environment 404, a secrets:write caller 403, and the same name again
// records nothing new.
func TestServedSecretProjectAndEnvironmentRenameA235L3(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A235-L3 rename tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a235l3-admin", "secrets:read", "secrets:write", "access:write")
	member := seedScopedTokenSubject(t, h.store, h.tenant, "a235l3-member", "secrets:read", "secrets:write")
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "a235l3-outsider", "secrets:read", "secrets:write")

	call := func(tok, method, path string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReq(t, h, method, path, tok, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	const project = "/api/v1/secrets/projects/rename235"
	call(admin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "rename235", "name": "Payments", "environments": []any{
		map[string]any{"slug": "dev", "name": "Development"}, map[string]any{"slug": "prod", "name": "Production", "restricted": true},
	}}, http.StatusCreated)
	call(admin, http.MethodPut, project+"/members/a235l3-member", map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", member, "a235l3-put",
		map[string]any{"name": "rename235/prod/db/password", "value": "prod-db-secret"}); status != http.StatusCreated {
		t.Fatalf("member writes prod: HTTP %d %s", status, raw)
	}

	// The CLI renames the project; the API renames prod.
	dir := t.TempDir()
	nameFile := filepath.Join(dir, "name.json")
	if err := os.WriteFile(nameFile, []byte(`{"name":"Payments Platform"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(t.Context(), []string{"--server", h.ts.URL, "--token", admin, "--tenant", h.tenant,
		"secrets", "projects", "rename", "rename235", "-f", nameFile}, cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("trstctl secrets projects rename: %s%s", stdout.String(), stderr.String())
	}
	call(admin, http.MethodPost, project+"/environments/prod/rename", map[string]any{"name": "Live"}, http.StatusOK)

	type view struct {
		Slug         string `json:"slug"`
		Name         string `json:"name"`
		Environments []struct {
			Slug       string `json:"slug"`
			Name       string `json:"name"`
			Restricted bool   `json:"restricted"`
		} `json:"environments"`
		Members []struct {
			Subject      string   `json:"subject"`
			Environments []string `json:"environments"`
		} `json:"members"`
	}
	var got view
	if err := json.Unmarshal(call(admin, http.MethodGet, project, nil, http.StatusOK), &got); err != nil {
		t.Fatal(err)
	}
	envNames := map[string]string{}
	for _, env := range got.Environments {
		envNames[env.Slug] = env.Name
		if env.Slug == "prod" && !env.Restricted {
			t.Fatal("renaming prod lifted its restriction")
		}
	}
	if got.Slug != "rename235" || got.Name != "Payments Platform" || envNames["prod"] != "Live" || envNames["dev"] != "Development" {
		t.Fatalf("project after the renames = %+v", got)
	}
	if len(got.Members) != 1 || got.Members[0].Subject != "a235l3-member" || len(got.Members[0].Environments) != 1 || got.Members[0].Environments[0] != "prod" {
		t.Fatalf("members after the renames = %+v", got.Members)
	}
	// The secret keeps its name and value, and prod stays closed to non-members.
	var secret struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(call(member, http.MethodGet, "/api/v1/secrets/store/rename235/prod/db/password", nil, http.StatusOK), &secret); err != nil || secret.Value != "prod-db-secret" {
		t.Fatalf("the member's read after the renames = %q, %v", secret.Value, err)
	}
	call(outsider, http.MethodGet, "/api/v1/secrets/store/rename235/prod/db/password", nil, http.StatusNotFound)

	// Refusals.
	call(admin, http.MethodPost, project+"/rename", map[string]any{"name": "   "}, http.StatusBadRequest)
	call(admin, http.MethodPost, project+"/rename", map[string]any{"name": string(bytes.Repeat([]byte("n"), 129))}, http.StatusBadRequest)
	call(admin, http.MethodPost, "/api/v1/secrets/projects/nope235/rename", map[string]any{"name": "Nope"}, http.StatusNotFound)
	call(admin, http.MethodPost, project+"/environments/qa/rename", map[string]any{"name": "QA"}, http.StatusNotFound)
	call(member, http.MethodPost, project+"/rename", map[string]any{"name": "Mine"}, http.StatusForbidden)
	call(member, http.MethodPost, project+"/environments/prod/rename", map[string]any{"name": "Mine"}, http.StatusForbidden)

	// The same name again records nothing new.
	before := servedEventCount(t, h, "secret.project.renamed")
	call(admin, http.MethodPost, project+"/rename", map[string]any{"name": "Payments Platform"}, http.StatusOK)
	if after := servedEventCount(t, h, "secret.project.renamed"); after != before || before != 1 {
		t.Fatalf("secret.project.renamed events = %d then %d, want 1 and no new one for the same name", before, after)
	}
	if n := servedEventCount(t, h, "secret.project.environment_renamed"); n != 1 {
		t.Fatalf("secret.project.environment_renamed events = %d, want 1", n)
	}
	t.Log("A235L3_RENAME_OK project=rename235 name=Payments-Platform prod=Live")
}
