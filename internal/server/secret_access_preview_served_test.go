// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedDeveloperSecretAccessPreviewIsExactEffectFreeAndValueFree(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "served developer secret access preview tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	const userValue = "f64-user-must-never-escape"
	const passwordValue = "f64-password-must-never-escape"
	for _, seed := range []struct {
		name  string
		value string
	}{
		{name: "app/db/user", value: userValue},
		{name: "app/db/password", value: passwordValue},
		{name: "app/db/dsn", value: "postgres://${secret.app/db/user}:${secret.app/db/password}@db.internal/app"},
	} {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
			map[string]any{"name": seed.name, "value": seed.value})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", seed.name, status, body)
		}
	}
	before, err := h.store.GetSecret(t.Context(), h.tenant, "app/db/dsn")
	if err != nil {
		t.Fatalf("read source metadata before preview: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "app/db/dsn", "env_var": "DATABASE_URL", "resolve": true,
	})
	if status != http.StatusOK {
		t.Fatalf("preview status = %d body %s", status, body)
	}
	for _, forbidden := range []string{userValue, passwordValue, "postgres://"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("preview leaked secret material %q: %s", forbidden, body)
		}
	}
	var plan struct {
		Capability             string   `json:"capability"`
		Operation              string   `json:"operation"`
		Ready                  bool     `json:"ready"`
		EffectFree             bool     `json:"effect_free"`
		Name                   string   `json:"name"`
		Version                int      `json:"version"`
		EnvVar                 string   `json:"env_var"`
		Resolve                bool     `json:"resolve_references"`
		RequiredPermission     string   `json:"required_permission"`
		RequestFingerprint     string   `json:"request_fingerprint"`
		Blockers               []string `json:"blockers"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		CLIArgv                []string `json:"cli_argv"`
		TypeScript             string   `json:"typescript"`
		APIRequest             struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"api_request"`
		RecoverySteps     []string `json:"recovery_steps"`
		VerificationSteps []string `json:"verification_steps"`
		DataHandling      string   `json:"secret_data_handling"`
		BulkImport        struct {
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		} `json:"bulk_import"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode preview: %v (%s)", err, body)
	}
	if plan.Capability != "F64" || plan.Operation != "read_for_process" || !plan.Ready || !plan.EffectFree ||
		plan.Name != "app/db/dsn" || plan.Version != 1 || plan.EnvVar != "DATABASE_URL" || !plan.Resolve ||
		plan.RequiredPermission != "secrets:read" || !strings.HasPrefix(plan.RequestFingerprint, "sha256:") {
		t.Fatalf("unexpected access plan: %+v", plan)
	}
	wantArgv := []string{"trstctl", "run", "--secret", "DATABASE_URL=app/db/dsn", "--resolve", "--", "./service"}
	if !slices.Equal(plan.CLIArgv, wantArgv) {
		t.Fatalf("cli argv = %#v, want %#v", plan.CLIArgv, wantArgv)
	}
	if plan.APIRequest.Method != http.MethodGet || plan.APIRequest.Path != "/api/v1/secrets/store/app/db/dsn?resolve=true" {
		t.Fatalf("API request = %+v", plan.APIRequest)
	}
	if !strings.Contains(plan.TypeScript, `client.secrets.get("app/db/dsn", { resolve: true })`) ||
		strings.Contains(plan.TypeScript, userValue) || strings.Contains(plan.TypeScript, passwordValue) {
		t.Fatalf("TypeScript snippet is not the value-free served contract: %q", plan.TypeScript)
	}
	if len(plan.Blockers) != 0 || len(plan.PreviewWrites) != 0 || len(plan.PreviewExternalEffects) != 0 ||
		len(plan.RecoverySteps) == 0 || len(plan.VerificationSteps) == 0 || plan.DataHandling == "" ||
		plan.BulkImport.Available || plan.BulkImport.Reason == "" {
		t.Fatalf("preview did not publish the full safe boundary: %+v", plan)
	}
	after, err := h.store.GetSecret(t.Context(), h.tenant, "app/db/dsn")
	if err != nil {
		t.Fatalf("read source metadata after preview: %v", err)
	}
	if after.Version != before.Version || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("preview changed source metadata: before=%+v after=%+v", before, after)
	}
	if h.logContains(t, userValue) || h.logContains(t, passwordValue) || h.logContains(t, "postgres://") {
		t.Fatal("preview leaked resolved or source values into the event log")
	}

	status, replayBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "app/db/dsn", "env_var": "DATABASE_URL", "resolve": true,
	})
	if status != http.StatusOK || !strings.Contains(string(replayBody), plan.RequestFingerprint) {
		t.Fatalf("same request did not return stable exact-plan identity: status %d body %s", status, replayBody)
	}

	status, missingBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "other-tenant/only", "env_var": "DATABASE_URL", "resolve": true,
	})
	if status != http.StatusOK || !strings.Contains(string(missingBody), `"ready":false`) ||
		!strings.Contains(string(missingBody), "does not exist in this tenant") {
		t.Fatalf("missing/cross-tenant preview did not fail closed: status %d body %s", status, missingBody)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
		map[string]any{"name": "app/missing-reference", "value": "${secret.other-tenant/only}"})
	if status != http.StatusCreated {
		t.Fatalf("create missing-reference source: status %d body %s", status, body)
	}
	status, missingReferenceBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "app/missing-reference", "env_var": "DATABASE_URL", "resolve": true,
	})
	if status != http.StatusOK || !strings.Contains(string(missingReferenceBody), `"ready":false`) ||
		!strings.Contains(string(missingReferenceBody), "referenced secret does not exist") ||
		strings.Contains(string(missingReferenceBody), "named secret does not exist") {
		t.Fatalf("missing referenced secret was not distinguished from the source: status %d body %s", status, missingReferenceBody)
	}

	for _, seed := range []struct {
		name  string
		value string
	}{
		{name: "app/cycle-a", value: "${secret.app/cycle-b}"},
		{name: "app/cycle-b", value: "${secret.app/cycle-a}"},
	} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token,
			map[string]any{"name": seed.name, "value": seed.value})
		if status != http.StatusCreated {
			t.Fatalf("create %s: status %d body %s", seed.name, status, body)
		}
	}
	status, cycleBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "app/cycle-a", "env_var": "DATABASE_URL", "resolve": true,
	})
	if status != http.StatusOK || !strings.Contains(string(cycleBody), `"ready":false`) ||
		!strings.Contains(string(cycleBody), "found a cycle") {
		t.Fatalf("reference cycle did not fail closed with recovery guidance: status %d body %s", status, cycleBody)
	}

	status, invalidBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/access/preview", token, map[string]any{
		"name": "app/db/dsn", "env_var": "BAD-NAME", "resolve": true,
	})
	if status != http.StatusBadRequest || !strings.Contains(string(invalidBody), "environment variable") {
		t.Fatalf("invalid environment variable was accepted: status %d body %s", status, invalidBody)
	}
}
