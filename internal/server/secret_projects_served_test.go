// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// A235: two teams in one tenant cannot read each other's restricted
// environment values or references, on any surface that reads by name; a user
// sets up dev and stage from the CLI with no database edits and no hidden
// identifiers; the project view keeps the tenant boundary and names unknown
// ownership explicitly.
func TestServedSecretsWorkspaceKeepsRestrictedEnvironmentsToMembersA235(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "secrets-admin", "access:write", "secrets:read", "secrets:write")
	teamA := seedScopedTokenSubject(t, h.store, h.tenant, "team-a-ci", "secrets:read", "secrets:write")
	teamB := seedScopedTokenSubject(t, h.store, h.tenant, "team-b-ci", "secrets:read", "secrets:write")

	// Setup from the CLI: a project with dev (open) and stage (restricted), and
	// team A granted stage. Nothing but slugs is typed.
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cliRun := func(token string, args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := cli.Run(t.Context(), append([]string{"--server", h.ts.URL, "--token", token, "--tenant", h.tenant}, args...),
			cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	if code, out := cliRun(teamA, "secrets", "projects", "create", "-f", write("p.json",
		`{"slug":"payments","name":"Payments","environments":[{"slug":"dev"},{"slug":"stage","restricted":true}]}`)); code == 0 {
		t.Fatalf("a token without access:write created a project: %s", out)
	}
	if code, out := cliRun(admin, "secrets", "projects", "create", "-f", write("p.json",
		`{"slug":"payments","name":"Payments","environments":[{"slug":"dev"},{"slug":"stage","restricted":true}]}`)); code != 0 {
		t.Fatalf("create project: %s", out)
	}
	if code, out := cliRun(admin, "secrets", "projects", "members", "grant", "payments", "team-a-ci", "-f", write("g.json",
		`{"role":"developer","environments":["stage"]}`)); code != 0 {
		t.Fatalf("grant team A: %s", out)
	}
	if code, out := cliRun(teamB, "secrets", "projects", "members", "grant", "payments", "team-b-ci", "-f", write("g2.json",
		`{"role":"admin"}`)); code == 0 {
		t.Fatalf("team B granted itself the project: %s", out)
	}

	put := func(token, name, value string) int {
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "a235-"+name+"-"+token[len(token)-6:],
			map[string]any{"name": name, "value": value})
		return status
	}
	if status := put(teamA, "payments/stage/db/password", "stage-db-secret"); status != http.StatusCreated {
		t.Fatalf("team A writes stage: %d", status)
	}
	if status := put(teamA, "payments/dev/db/password", "dev-db-secret"); status != http.StatusCreated {
		t.Fatalf("team A writes dev: %d", status)
	}
	if status := put(teamB, "payments/stage/db/other", "x"); status != http.StatusForbidden {
		t.Fatalf("team B wrote into stage: %d", status)
	}
	if status := put(teamB, "team-b/app/config", "dsn=${secret.payments/stage/db/password}"); status != http.StatusCreated {
		t.Fatalf("team B writes its own secret: %d", status)
	}
	if status := put(teamB, "shared/token", "shared"); status != http.StatusCreated {
		t.Fatalf("tenant-level secret: %d", status)
	}

	get := func(token, path string) (int, string) {
		status, body := secretsReq(t, h, http.MethodGet, path, token, nil)
		return status, string(body)
	}
	// Team B: every way of reading the restricted secret answers as missing.
	for name, path := range map[string]string{
		"read":      "/api/v1/secrets/store/payments/stage/db/password",
		"resolve":   "/api/v1/secrets/store/payments/stage/db/password?resolve=true",
		"reference": "/api/v1/secrets/store/team-b/app/config?resolve=true",
		"history":   "/api/v1/secrets/store/history/payments/stage/db/password?version=1",
	} {
		if status, body := get(teamB, path); status != http.StatusNotFound || strings.Contains(body, "stage-db-secret") {
			t.Fatalf("team B %s: HTTP %d %s", name, status, body)
		}
	}
	if status, body := q6VaultRequest(t, h, teamB, http.MethodGet, "/v1/secret/data/payments/stage/db/password"); status != http.StatusNotFound || strings.Contains(string(body), "stage-db-secret") {
		t.Fatalf("team B KV read: HTTP %d %s", status, body)
	}
	if _, body := get(teamB, "/api/v1/secrets/store"); strings.Contains(body, "payments/stage/") || !strings.Contains(body, "payments/dev/db/password") {
		t.Fatalf("team B's listing: %s", body)
	}
	if _, body := q6VaultRequest(t, h, teamB, http.MethodGet, "/v1/secret/metadata/payments?list=true"); strings.Contains(string(body), "stage") {
		t.Fatalf("team B's KV listing names stage: %s", body)
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", teamB, map[string]any{"name": "payments/stage/db/password", "env_var": "DB_PASSWORD"})
	if status != http.StatusOK || !strings.Contains(string(body), "does not exist") {
		t.Fatalf("team B access preview: HTTP %d %s", status, body)
	}
	for name, req := range map[string]struct {
		method, path string
		body         any
		want         int
	}{
		"rotate": {http.MethodPut, "/api/v1/secrets/store/payments/stage/db/password", map[string]any{"value": "x"}, http.StatusForbidden},
		"delete": {http.MethodDelete, "/api/v1/secrets/store/payments/stage/db/password", nil, http.StatusForbidden},
		"sync":   {http.MethodPost, "/api/v1/secrets/syncs", map[string]any{"name": "payments/stage/db/password", "target": "webhook", "remote_key": "x"}, http.StatusNotFound},
	} {
		if status, body := secretsReqKey(t, h, req.method, req.path, teamB, "a235-b-"+name, req.body); status != req.want {
			t.Fatalf("team B %s: HTTP %d %s, want %d", name, status, body, req.want)
		}
	}

	// Team A, granted stage, reads it; both teams read dev and tenant-level secrets.
	if status, body := get(teamA, "/api/v1/secrets/store/payments/stage/db/password"); status != http.StatusOK || !strings.Contains(body, "stage-db-secret") {
		t.Fatalf("team A reads stage: HTTP %d", status)
	}
	if status, body := get(teamB, "/api/v1/secrets/store/payments/dev/db/password"); status != http.StatusOK || !strings.Contains(body, "dev-db-secret") {
		t.Fatalf("team B reads dev: HTTP %d", status)
	}
	if status, _ := get(teamA, "/api/v1/secrets/store/shared/token"); status != http.StatusOK {
		t.Fatalf("tenant-level secret: HTTP %d", status)
	}

	// The project view: owners are named or "unknown"; stage is listed only to members.
	view := func(token string) (out struct {
		Owner        string `json:"owner"`
		Environments []struct {
			Slug    string `json:"slug"`
			Access  string `json:"access"`
			Secrets []struct {
				Name  string `json:"name"`
				Owner string `json:"owner"`
			} `json:"secrets"`
		} `json:"environments"`
	}) {
		t.Helper()
		code, text := cliRun(token, "secrets", "projects", "show", "payments")
		if code != 0 {
			t.Fatalf("show: %s", text)
		}
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("show output: %v %s", err, text)
		}
		return out
	}
	byEnv := func(v any) map[string]string {
		raw, _ := json.Marshal(v)
		var envs []struct {
			Slug    string            `json:"slug"`
			Access  string            `json:"access"`
			Secrets []json.RawMessage `json:"secrets"`
		}
		_ = json.Unmarshal(raw, &envs)
		out := map[string]string{}
		for _, e := range envs {
			out[e.Slug] = e.Access + "/" + strconv.Itoa(len(e.Secrets))
		}
		return out
	}
	b := view(teamB)
	if got := byEnv(b.Environments); got["dev"] != "open/1" || got["stage"] != "restricted/0" || b.Owner != "unknown" {
		t.Fatalf("team B's view: owner %q envs %v", b.Owner, got)
	}
	a := view(teamA)
	if got := byEnv(a.Environments); got["stage"] != "member/1" || a.Environments[1].Secrets[0].Owner != "unknown" {
		t.Fatalf("team A's view: %v", got)
	}

	// Revoking team A closes stage to it too.
	if code, out := cliRun(admin, "secrets", "projects", "members", "revoke", "payments", "team-a-ci", "--force"); code != 0 {
		t.Fatalf("revoke: %s", out)
	}
	if status, _ := get(teamA, "/api/v1/secrets/store/payments/stage/db/password"); status != http.StatusNotFound {
		t.Fatalf("team A after revocation: HTTP %d", status)
	}
	t.Logf("A235_OK")
}
