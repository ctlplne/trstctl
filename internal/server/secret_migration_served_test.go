// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A243 through the served API, end to end: a seeded multi-environment export
// (dotenv, YAML and JSON) with nested and cross-environment references,
// multiline values and metadata is assessed without values, staged by its
// digest while the export's system stays each secret's one writer, its
// permissions are applied under access:write only as translated, its
// consumer's reads are observed, it cuts over, a credential the export could
// not carry is reissued rather than migrated, and the run rolls back from its
// manifest. No value reaches the logs.
func TestServedSecretMigrationJourneyA243(t *testing.T) {
	logs := &p6MoveLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "migration-admin", "access:write", "secrets:read", "secrets:write")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "migration-operator", "secrets:read", "secrets:write")
	app := seedScopedTokenSubject(t, h.store, h.tenant, "orders-api", "secrets:read")

	call := func(token, method, path, key string, body any) (int, map[string]any) {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, key, body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"raw": string(raw)}
		}
		return status, out
	}
	mustStatus := func(want, got int, out map[string]any, what string) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: HTTP %d %v", what, got, out)
		}
	}
	status, out := call(admin, http.MethodPost, "/api/v1/secrets/projects", "a243-project", map[string]any{
		"slug": "migrate243", "environments": []map[string]any{{"slug": "production", "restricted": true}, {"slug": "staging", "restricted": true}},
	})
	mustStatus(http.StatusCreated, status, out, "create project")
	for _, subject := range []string{"migration-admin", "migration-operator"} {
		status, out = call(admin, http.MethodPut, "/api/v1/secrets/projects/migrate243/members/"+subject, "a243-member-"+subject,
			map[string]any{"role": "developer"})
		mustStatus(http.StatusOK, status, out, "grant "+subject)
	}
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/store", "a243-seed", map[string]any{
		"name": "migrate243/production/api/DB_HOST", "value": "old-host.internal"})
	mustStatus(http.StatusCreated, status, out, "seed an existing secret")

	bundle := map[string]any{
		"project": "migrate243",
		"sources": []map[string]any{
			{"environment": "production", "folder": "api", "format": "dotenv", "content": "# primary database host\n# @owner: orders-team\nDB_HOST=db.prod.internal\nDB_PORT=5432\nDB_URL=\"postgres://app@${DB_HOST}:${DB_PORT}/orders\"\nTLS_BUNDLE=\"-----BEGIN CERTIFICATE-----\nTUlJQ2Zha2U=\n-----END CERTIFICATE-----\"\n# @exportable: false\nSIGNING_KEY=\n"},
			{"environment": "staging", "format": "yaml", "content": "api:\n  CHAIN_A: \"${CHAIN_B}\"\n  CHAIN_B: \"${production:api/DB_HOST}\"\n  NOTES:\n    $value: |\n      line one\n      line two\n    $description: two-line note\n"},
			{"environment": "production", "format": "json", "content": `{"shared": {"REGION": "eu-west-1"}}`},
		},
		"permissions": []map[string]any{
			{"subject": "orders-api", "environment": "production", "access": "read"},
			{"subject": "billing-batch", "environment": "production", "folder": "api", "access": "read"},
		},
		"consumers": []map[string]any{
			{"name": "orders", "subject": "orders-api", "environment": "production", "secrets": []string{"api/DB_URL", "shared/REGION"}},
		},
	}
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/assess", "a243-assess", bundle)
	mustStatus(http.StatusCreated, status, out, "assess")
	id, _ := out["id"].(string)
	digest, _ := out["digest"].(string)
	if id == "" || digest == "" {
		t.Fatalf("assess answered %v", out)
	}
	plan := out["plan"].(map[string]any)
	counts := plan["counts"].(map[string]any)
	if counts["import"].(float64) != 8 || counts["reissue"].(float64) != 1 || counts["permissions_held"].(float64) != 1 {
		t.Fatalf("assessment counts = %v", counts)
	}

	stage := func(key, planDigest string) (int, map[string]any) {
		body := map[string]any{"plan_digest": planDigest}
		for k, v := range bundle {
			body[k] = v
		}
		return call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/stage", key, body)
	}
	status, out = stage("a243-stage-stale", strings.Repeat("0", 64))
	if status != http.StatusConflict || !strings.Contains(toJSON(out), "plan_stale") {
		t.Fatalf("a stale digest staged: %d %v", status, out)
	}
	status, out = stage("a243-stage", digest)
	mustStatus(http.StatusOK, status, out, "stage")
	objects := map[string]map[string]any{}
	for _, o := range out["objects"].([]any) {
		objects[o.(map[string]any)["name"].(string)] = o.(map[string]any)
	}
	if host := objects["migrate243/production/api/DB_HOST"]; host["prior_version"].(float64) != 1 || host["version"].(float64) != 2 || host["writer"] != "source" {
		t.Fatalf("an existing secret's staging: %v", host)
	}
	if len(objects) != 8 || out["state"] != "staged" {
		t.Fatalf("staged run: %v", out)
	}

	// One writer per secret: the store refuses its own write until cutover.
	status, out = call(operator, http.MethodPut, "/api/v1/secrets/store/migrate243/production/api/DB_PORT", "a243-native-write",
		map[string]any{"value": "6543"})
	if status != http.StatusConflict || !strings.Contains(toJSON(out), "migration_source_writer") {
		t.Fatalf("a native write to a staged secret: %d %v", status, out)
	}
	// References were translated, not flattened: they resolve through the store.
	status, out = call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/production/api/DB_URL?resolve=true", "", nil)
	if status != http.StatusOK || out["value"] != "postgres://app@db.prod.internal:5432/orders" {
		t.Fatalf("resolved DB_URL: %d %v", status, out)
	}
	status, out = call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/staging/api/CHAIN_A?resolve=true", "", nil)
	if status != http.StatusOK || out["value"] != "db.prod.internal" {
		t.Fatalf("a nested cross-environment chain: %d %v", status, out)
	}
	status, out = call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/staging/api/NOTES", "", nil)
	if status != http.StatusOK || out["value"] != "line one\nline two\n" {
		t.Fatalf("a multiline value: %d %v", status, out)
	}

	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/cutover", "a243-cutover-early", nil)
	if status != http.StatusConflict || !strings.Contains(toJSON(out), "consumers_pending") {
		t.Fatalf("cutover before the consumer read: %d %v", status, out)
	}
	// Permissions: access:write applies only the translated grant.
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/permissions", "a243-perms-denied", nil)
	if status != http.StatusForbidden {
		t.Fatalf("a secrets:write token applied memberships: %d %v", status, out)
	}
	status, out = call(admin, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/permissions", "a243-perms", nil)
	mustStatus(http.StatusOK, status, out, "apply permissions")
	if applied := toJSON(out["permissions_applied"]); !strings.Contains(applied, "orders-api") || strings.Contains(applied, "billing-batch") {
		t.Fatalf("applied grants = %s", applied)
	}
	// The consumer reads what it is expected to, as itself.
	for _, name := range []string{"migrate243/production/api/DB_URL", "migrate243/production/shared/REGION"} {
		if status, out := call(app, http.MethodGet, "/api/v1/secrets/store/"+name, "", nil); status != http.StatusOK {
			t.Fatalf("the consumer reads %s: %d %v", name, status, out)
		}
	}
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/cutover", "a243-cutover", nil)
	mustStatus(http.StatusOK, status, out, "cutover")
	if out["state"] != "cut-over" || strings.Contains(toJSON(out["objects"]), `"writer":"source"`) {
		t.Fatalf("cut over run: %v", out)
	}
	status, out = call(operator, http.MethodPut, "/api/v1/secrets/store/migrate243/production/api/DB_PORT", "a243-native-write-2",
		map[string]any{"value": "6543"})
	mustStatus(http.StatusOK, status, out, "a native write after cutover")

	// The credential the export could not carry is reissued, never migrated.
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/reissue", "a243-reissue",
		map[string]any{"names": []string{"migrate243/production/api/SIGNING_KEY"}})
	mustStatus(http.StatusOK, status, out, "reissue")
	if !strings.Contains(toJSON(out["objects"]), `"name":"migrate243/production/api/SIGNING_KEY","outcome":"reissued"`) {
		t.Fatalf("reissued object: %v", out["objects"])
	}
	status, out = call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/production/api/SIGNING_KEY", "", nil)
	if status != http.StatusOK || len(out["value"].(string)) != 43 {
		t.Fatalf("the reissued credential: %d", status)
	}

	// Rollback from the manifest: the found version comes back, what the run
	// created goes, and what was written since is kept.
	status, out = call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/rollback", "a243-rollback", nil)
	mustStatus(http.StatusOK, status, out, "rollback")
	rolledBack := toJSON(out["objects"])
	rolled := map[string]string{}
	for _, o := range out["objects"].([]any) {
		rolled[o.(map[string]any)["name"].(string)] = o.(map[string]any)["rollback"].(string)
	}
	if rolled["migrate243/production/api/DB_HOST"] != "restored" || rolled["migrate243/production/api/DB_URL"] != "deleted" ||
		rolled["migrate243/production/api/DB_PORT"] != "kept" || rolled["migrate243/production/api/SIGNING_KEY"] != "deleted" || out["state"] != "rolled-back" {
		t.Fatalf("rollback = %v", rolled)
	}
	status, out = call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/production/api/DB_HOST", "", nil)
	if status != http.StatusOK || out["value"] != "old-host.internal" {
		t.Fatalf("the restored secret: %d %v", status, out)
	}
	if status, _ := call(operator, http.MethodGet, "/api/v1/secrets/store/migrate243/production/api/DB_URL", "", nil); status != http.StatusNotFound {
		t.Fatalf("a created secret survived the rollback: %d", status)
	}
	// A retried rollback converges on the same evidence.
	status, again := call(operator, http.MethodPost, "/api/v1/secrets/migrations/"+id+"/rollback", "a243-rollback", nil)
	if status != http.StatusOK || toJSON(again["objects"]) != rolledBack {
		t.Fatalf("a retried rollback: %d %v", status, again)
	}

	for _, value := range []string{"db.prod.internal", "5432", "TUlJQ2Zha2U=", "line one", "eu-west-1", "old-host.internal", "postgres://app@"} {
		if strings.Contains(logs.String(), value) {
			t.Fatalf("the server logged the value %q", value)
		}
	}
}

func toJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
