// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

type restorePlanView struct {
	PlanDigest string `json:"plan_digest"`
	Items      []struct {
		Name           string `json:"name"`
		CurrentVersion int    `json:"current_version"`
		RestoreVersion int    `json:"restore_version"`
		Action         string `json:"action"`
		Reason         string `json:"reason"`
	} `json:"items"`
	Changes int `json:"changes"`
	Blocked int `json:"blocked"`
}

func (p restorePlanView) action(name string) (string, string) {
	for _, item := range p.Items {
		if item.Name == name {
			return item.Action, item.Reason
		}
	}
	return "", ""
}

// A236: a folder restore puts one folder back to a point in time as one batch
// of new, audited versions; it never touches a secret outside the folder or
// deletes one created since, refuses a version whose credential a rotation
// retired, and a change after the preview makes the plan stale.
func TestServedSecretFolderRestoreIsAtomicAndRefusesRetiredCredentialsA236(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "restore-admin", "access:write", "secrets:read", "secrets:write")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "restorer", "secrets:read", "secrets:write")
	dir := t.TempDir()
	cliRun := func(token string, args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := cli.Run(t.Context(), append([]string{"--server", h.ts.URL, "--token", token, "--tenant", h.tenant}, args...),
			cli.Env{HTTPClient: h.ts.Client()}, nil, &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	bodyFile := func(name string, body any) string {
		raw, _ := json.Marshal(body)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if code, out := cliRun(admin, "secrets", "projects", "create", "-f", bodyFile("p.json", map[string]any{
		"slug": "ledger", "environments": []map[string]any{{"slug": "dev"}},
	})); code != 0 {
		t.Fatalf("create project: %s", out)
	}
	write := func(method, name, value string) {
		t.Helper()
		path, body := "/api/v1/secrets/store", map[string]any{"name": name, "value": value}
		want := http.StatusCreated
		if method == http.MethodPut {
			path, body, want = "/api/v1/secrets/store/"+name, map[string]any{"value": value}, http.StatusOK
		}
		if status, raw := secretsReqKey(t, h, method, path, operator, "a236r-"+method+"-"+name+"-"+value, body); status != want {
			t.Fatalf("%s %s: HTTP %d %s", method, name, status, raw)
		}
	}
	read := func(name string) string {
		_, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name+"?resolve=true", operator, nil)
		return string(body)
	}
	write(http.MethodPost, "ledger/dev/db/password", "pw-one")
	write(http.MethodPost, "ledger/dev/db/url", "postgres://app:${secret.ledger/dev/db/password}@db")
	write(http.MethodPost, "ledger/dev/db/creds", "creds-one")
	write(http.MethodPost, "ledger/dev/app/token", "tok-one")
	time.Sleep(20 * time.Millisecond)
	at := time.Now().UTC()
	time.Sleep(20 * time.Millisecond)
	write(http.MethodPut, "ledger/dev/db/password", "pw-two")
	write(http.MethodPut, "ledger/dev/db/url", "postgres://u2:${secret.ledger/dev/db/password}@db")
	write(http.MethodPost, "ledger/dev/db/new", "new-one")
	write(http.MethodPut, "ledger/dev/app/token", "tok-two")

	preview := func(req map[string]any) (int, restorePlanView, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/ledger/restores/preview", operator, req)
		var plan restorePlanView
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &plan); err != nil {
				t.Fatalf("plan: %v %s", err, body)
			}
		}
		return status, plan, string(body)
	}
	apply := func(key string, req map[string]any) (int, string) {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/ledger/restores", operator, key, req)
		return status, string(body)
	}
	req := map[string]any{"environment": "dev", "folder": "db", "at": at.Format(time.RFC3339Nano)}
	status, plan, raw := preview(req)
	if status != http.StatusOK {
		t.Fatalf("preview: HTTP %d %s", status, raw)
	}
	for _, value := range []string{"postgres://", "pw-one", "pw-two", "creds-one", "tok-one", "tok-two", "new-one"} {
		if strings.Contains(raw, value) {
			t.Fatalf("the restore preview carries a value (%q): %s", value, raw)
		}
	}
	for name, want := range map[string]string{
		"ledger/dev/db/password": "restore", "ledger/dev/db/url": "restore",
		"ledger/dev/db/creds": "unchanged", "ledger/dev/db/new": "created_since",
	} {
		if got, _ := plan.action(name); got != want {
			t.Fatalf("%s: %q, want %q: %s", name, got, want, raw)
		}
	}
	if a, _ := plan.action("ledger/dev/app/token"); a != "" || plan.Changes != 2 {
		t.Fatalf("the restore reaches outside its folder: %s", raw)
	}

	// A change after the preview makes the plan stale.
	write(http.MethodPut, "ledger/dev/db/url", "postgres://u3:${secret.ledger/dev/db/password}@db")
	if status, body := apply("a236r-stale", map[string]any{"environment": "dev", "folder": "db", "at": req["at"],
		"plan_digest": plan.PlanDigest}); status != http.StatusConflict || !strings.Contains(body, "plan_stale") {
		t.Fatalf("stale restore: HTTP %d %s", status, body)
	}

	_, plan, _ = preview(req)
	status, receipt := apply("a236r-apply", map[string]any{"environment": "dev", "folder": "db", "at": req["at"], "plan_digest": plan.PlanDigest})
	if status != http.StatusCreated {
		t.Fatalf("restore: HTTP %d %s", status, receipt)
	}
	if body := read("ledger/dev/db/url"); !strings.Contains(body, "postgres://app:pw-one@db") {
		t.Fatalf("restored folder does not read as it stood: %s", body)
	}
	pw, err := h.store.GetSecret(t.Context(), h.tenant, "ledger/dev/db/password")
	if err != nil || pw.Version != 3 {
		t.Fatalf("restore did not write a new version: %+v %v", pw, err)
	}
	if v, err := h.store.GetSecretVersion(t.Context(), h.tenant, "ledger/dev/db/password", 3); err != nil ||
		v.RecoveredFromVersion == nil || *v.RecoveredFromVersion != 1 {
		t.Fatalf("restored version does not name its source: %+v %v", v, err)
	}
	if body := read("ledger/dev/app/token"); !strings.Contains(body, "tok-two") {
		t.Fatalf("a secret outside the folder changed: %s", body)
	}
	if rec, _ := h.store.GetSecret(t.Context(), h.tenant, "ledger/dev/db/new"); rec.Version != 1 {
		t.Fatalf("a secret created since was touched: %+v", rec)
	}
	if !h.hasEvent(t, "secret.batch_versioned") || h.logContains(t, "postgres://app:p1@db") {
		t.Fatal("the restore event is missing or a value reached the logs")
	}

	// A version whose credential a rotation retired at its provider is refused
	// by name, and nothing in the folder changes.
	creds, _ := h.store.GetSecret(t.Context(), h.tenant, "ledger/dev/db/creds")
	write(http.MethodPut, "ledger/dev/db/creds", "creds-two")
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO secret_static_rotation_commands
			(tenant_id, id, tenant_epoch, provider, secret_key, old_ref, phase, expected_version, result_version,
			 idempotency_key_digest, request_binding, created_at, updated_at)
			VALUES ($1, '9e783bba-616c-5da7-b334-8235249d5899', 'epoch', 'pg', $2, 'old', 'completed', $3, $4, $5, $5, now(), now())`,
			h.tenant, "ledger/dev/db/creds", creds.Version, creds.Version+1, strings.Repeat("a", 64))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, plan, raw = preview(req)
	if a, reason := plan.action("ledger/dev/db/creds"); a != "blocked" || !strings.Contains(reason, "retired at its provider") {
		t.Fatalf("a retired credential was not refused: %s", raw)
	}
	if status, body := apply("a236r-blocked", map[string]any{"environment": "dev", "folder": "db", "at": req["at"],
		"plan_digest": plan.PlanDigest}); status != http.StatusConflict || !strings.Contains(body, "plan_blocked") {
		t.Fatalf("blocked restore: HTTP %d %s", status, body)
	}
	if body := read("ledger/dev/db/creds"); !strings.Contains(body, "creds-two") {
		t.Fatalf("a blocked restore changed the folder: %s", body)
	}

	// The CLI drives the same reviewed flow.
	code, out := cliRun(operator, "secrets", "projects", "restore", "preview", "ledger", "-f",
		bodyFile("rp.json", map[string]any{"environment": "dev", "folder": "app", "at": req["at"]}))
	var cliPlan restorePlanView
	if code != 0 || json.Unmarshal([]byte(out), &cliPlan) != nil || cliPlan.Changes != 1 {
		t.Fatalf("cli preview: %s", out)
	}
	if code, out := cliRun(operator, "secrets", "projects", "restore", "apply", "ledger", "-f",
		bodyFile("ra.json", map[string]any{"environment": "dev", "folder": "app", "at": req["at"], "plan_digest": cliPlan.PlanDigest})); code != 0 {
		t.Fatalf("cli apply: %s", out)
	}
	if body := read("ledger/dev/app/token"); !strings.Contains(body, "tok-one") {
		t.Fatalf("cli restore: %s", body)
	}
	t.Logf("A236_RESTORE_OK")
}
