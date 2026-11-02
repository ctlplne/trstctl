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

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type promotionPlanView struct {
	PlanDigest string `json:"plan_digest"`
	Items      []struct {
		Key                 string   `json:"key"`
		TargetName          string   `json:"target_name"`
		TargetVersion       int      `json:"target_version"`
		Action              string   `json:"action"`
		Reason              string   `json:"reason"`
		References          []string `json:"references"`
		RewrittenReferences int      `json:"rewritten_references"`
	} `json:"items"`
	Kept    []string `json:"kept"`
	Changes int      `json:"changes"`
	Blocked int      `json:"blocked"`
}

func (p promotionPlanView) action(key string) (string, string) {
	for _, item := range p.Items {
		if item.Key == key {
			return item.Action, item.Reason
		}
	}
	return "", ""
}

// A236: an environment promotion is planned value-free, applied by its digest
// as one batch of new versions, points references into the source environment
// at the target, keeps target-only secrets, and fails closed on a cycle, a
// reference hop the caller may not read, a reference that exists only in
// another tenant, and a concurrent edit.
func TestServedSecretPromotionAppliesReviewedPlanAndFailsClosedA236(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "promo-admin", "access:write", "secrets:read", "secrets:write")
	promoter := seedScopedTokenSubject(t, h.store, h.tenant, "promoter", "secrets:read", "secrets:write")
	vaultTeam := seedScopedTokenSubject(t, h.store, h.tenant, "vault-team", "secrets:read", "secrets:write")

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
		"slug": "orders", "environments": []map[string]any{{"slug": "dev"}, {"slug": "stage"}, {"slug": "vault", "restricted": true}},
	})); code != 0 {
		t.Fatalf("create project: %s", out)
	}
	if code, out := cliRun(admin, "secrets", "projects", "members", "grant", "orders", "vault-team", "-f",
		bodyFile("g.json", map[string]any{"role": "developer", "environments": []string{"vault"}})); code != 0 {
		t.Fatalf("grant: %s", out)
	}
	put := func(token, name, value string) {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "a236-put-"+name,
			map[string]any{"name": name, "value": value}); status != http.StatusCreated {
			t.Fatalf("put %s: HTTP %d %s", name, status, body)
		}
	}
	read := func(name string) (int, string) {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/"+name+"?resolve=true", promoter, nil)
		return status, string(body)
	}
	put(promoter, "orders/dev/db/password", "dev-db-pass")
	put(promoter, "orders/dev/db/url", "postgres://app:${secret.orders/dev/db/password}@db/app")
	put(promoter, "orders/dev/app/token", "bearer ${secret.orders-shared/token}")
	put(promoter, "orders-shared/token", "tenant-token")
	put(promoter, "orders/stage/db/password", "stage-db-pass-old")
	put(promoter, "orders/stage/only-in-stage", "keep me")
	put(vaultTeam, "orders/vault/api-key", "vault-only")

	preview := func(token string, req map[string]any) (int, promotionPlanView, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/orders/promotions/preview", token, req)
		var plan promotionPlanView
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &plan); err != nil {
				t.Fatalf("plan: %v %s", err, body)
			}
		}
		return status, plan, string(body)
	}
	apply := func(key string, req map[string]any) (int, string) {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/orders/promotions", promoter, key, req)
		return status, string(body)
	}

	// The plan: value-free, references into dev rewritten, target-only kept.
	status, plan, raw := preview(promoter, map[string]any{"from": "dev", "to": "stage"})
	if status != http.StatusOK {
		t.Fatalf("preview: HTTP %d %s", status, raw)
	}
	for _, leaked := range []string{"dev-db-pass", "stage-db-pass-old", "tenant-token", "keep me"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("preview carries a value: %s", raw)
		}
	}
	if a, _ := plan.action("db/password"); a != "update" {
		t.Fatalf("db/password action %q: %s", a, raw)
	}
	if a, _ := plan.action("db/url"); a != "create" {
		t.Fatalf("db/url action %q: %s", a, raw)
	}
	if a, _ := plan.action("app/token"); a != "create" {
		t.Fatalf("app/token action %q: %s", a, raw)
	}
	if plan.Changes != 3 || plan.Blocked != 0 || len(plan.Kept) != 1 || plan.Kept[0] != "orders/stage/only-in-stage" {
		t.Fatalf("plan totals: %s", raw)
	}

	// A concurrent edit after the preview makes the reviewed digest stale.
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/orders/dev/db/password", promoter,
		"a236-rotate-dev", map[string]any{"value": "dev-db-pass-2"}); status != http.StatusOK {
		t.Fatalf("rotate dev: HTTP %d %s", status, body)
	}
	if status, body := apply("a236-apply-stale", map[string]any{"from": "dev", "to": "stage", "plan_digest": plan.PlanDigest}); status != http.StatusConflict ||
		!strings.Contains(body, "plan_stale") {
		t.Fatalf("stale apply: HTTP %d %s", status, body)
	}
	if _, body := read("orders/stage/db/password"); !strings.Contains(body, "stage-db-pass-old") {
		t.Fatalf("a stale plan changed the target: %s", body)
	}

	// The re-reviewed plan applies as one batch of new versions.
	_, plan, _ = preview(promoter, map[string]any{"from": "dev", "to": "stage"})
	req := map[string]any{"from": "dev", "to": "stage", "plan_digest": plan.PlanDigest}
	status, receipt := apply("a236-apply", req)
	if status != http.StatusCreated || !strings.Contains(receipt, `"batch_id"`) {
		t.Fatalf("apply: HTTP %d %s", status, receipt)
	}
	if _, body := read("orders/stage/db/url"); !strings.Contains(body, "postgres://app:dev-db-pass-2@db/app") {
		t.Fatalf("the promoted reference does not resolve in stage: %s", body)
	}
	if _, body := read("orders/stage/app/token"); !strings.Contains(body, "bearer tenant-token") {
		t.Fatalf("a tenant-level reference was not kept: %s", body)
	}
	if rec, err := h.store.GetSecret(t.Context(), h.tenant, "orders/stage/db/password"); err != nil || rec.Version != 2 {
		t.Fatalf("stage db/password version: %+v %v", rec, err)
	}
	if rec, err := h.store.GetSecret(t.Context(), h.tenant, "orders/stage/only-in-stage"); err != nil || rec.Version != 1 {
		t.Fatalf("a target-only secret was touched: %+v %v", rec, err)
	}
	if status, again := apply("a236-apply", req); status != http.StatusCreated || again != receipt {
		t.Fatalf("exact retry: HTTP %d %s, want %s", status, again, receipt)
	}
	if rec, _ := h.store.GetSecret(t.Context(), h.tenant, "orders/stage/db/password"); rec.Version != 2 {
		t.Fatalf("an exact retry wrote again: version %d", rec.Version)
	}
	if !h.hasEvent(t, "secret.batch_versioned") || h.logContains(t, "dev-db-pass-2") {
		t.Fatal("the promotion event is missing or a value reached the logs")
	}
	_, plan, raw = preview(promoter, map[string]any{"from": "dev", "to": "stage"})
	if plan.Changes != 0 {
		t.Fatalf("a repeated preview still changes: %s", raw)
	}
	if status, body := apply("a236-apply-noop", map[string]any{"from": "dev", "to": "stage", "plan_digest": plan.PlanDigest}); status != http.StatusOK ||
		strings.Contains(body, `"batch_id"`) {
		t.Fatalf("nothing to promote: HTTP %d %s", status, body)
	}

	// Fail closed: a cycle, a hop into a restricted environment the promoter is
	// not granted, a reference that exists only in another tenant, and a
	// missing reference. Each folder's plan is blocked and nothing is written.
	const tenantB = "22222222-2222-4222-8222-222222222236"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: tenantB, Name: "a236-tenant-b"}); err != nil {
		t.Fatal(err)
	}
	tokenB := seedScopedTokenSubject(t, h.store, tenantB, "tenant-b", "secrets:read", "secrets:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tokenB, "a236-b",
		map[string]any{"name": "other/creds", "value": "tenant-b-secret"}); status != http.StatusCreated {
		t.Fatalf("tenant B secret: HTTP %d %s", status, body)
	}
	put(promoter, "orders/dev/loop/a", "${secret.orders/dev/loop/b}")
	put(promoter, "orders/dev/loop/b", "${secret.orders/dev/loop/a}")
	put(promoter, "orders/dev/denied/key", "${secret.orders/vault/api-key}")
	put(promoter, "orders/dev/xtenant/creds", "${secret.other/creds}")
	put(promoter, "orders/dev/missing/creds", "${secret.orders/stage/never-written}")
	for folder, want := range map[string]string{
		"loop":    "reference cycle: orders/stage/loop/",
		"denied":  "${secret.orders/vault/api-key} does not resolve in the target",
		"xtenant": "${secret.other/creds} does not resolve in the target",
		"missing": "${secret.orders/stage/never-written} does not resolve in the target",
	} {
		status, plan, raw := preview(promoter, map[string]any{"from": "dev", "to": "stage", "folder": folder})
		if status != http.StatusOK || plan.Blocked == 0 || !strings.Contains(raw, want) || strings.Contains(raw, "vault-only") ||
			strings.Contains(raw, "tenant-b-secret") {
			t.Fatalf("%s preview: HTTP %d %s", folder, status, raw)
		}
		if status, body := apply("a236-blocked-"+folder, map[string]any{"from": "dev", "to": "stage", "folder": folder,
			"plan_digest": plan.PlanDigest}); status != http.StatusConflict || !strings.Contains(body, "plan_blocked") {
			t.Fatalf("%s apply: HTTP %d %s", folder, status, body)
		}
		names, err := h.store.ListSecretNamesUnder(t.Context(), h.tenant, []string{"orders/stage/" + folder + "/"}, nil, 10)
		if err != nil || len(names) != 0 {
			t.Fatalf("a blocked %s promotion wrote %v (%v)", folder, names, err)
		}
	}

	// The environments themselves: a non-member may not promote into or out of
	// a restricted environment.
	if status, _, raw := preview(promoter, map[string]any{"from": "dev", "to": "vault"}); status != http.StatusForbidden {
		t.Fatalf("promote into a restricted environment as a non-member: HTTP %d %s", status, raw)
	}
	if status, _, raw := preview(promoter, map[string]any{"from": "vault", "to": "stage"}); status != http.StatusForbidden {
		t.Fatalf("promote out of a restricted environment as a non-member: HTTP %d %s", status, raw)
	}

	// The CLI drives the same reviewed flow.
	put(promoter, "orders/dev/cli/flag", "on")
	code, out := cliRun(promoter, "secrets", "projects", "promote", "preview", "orders", "-f",
		bodyFile("pv.json", map[string]any{"from": "dev", "to": "stage", "folder": "cli"}))
	var cliPlan promotionPlanView
	if code != 0 || json.Unmarshal([]byte(out), &cliPlan) != nil || cliPlan.Changes != 1 {
		t.Fatalf("cli preview: %s", out)
	}
	if code, out := cliRun(promoter, "secrets", "projects", "promote", "apply", "orders", "-f",
		bodyFile("ap.json", map[string]any{"from": "dev", "to": "stage", "folder": "cli", "plan_digest": cliPlan.PlanDigest})); code != 0 {
		t.Fatalf("cli apply: %s", out)
	}
	if status, body := read("orders/stage/cli/flag"); status != http.StatusOK || !strings.Contains(body, `"on"`) {
		t.Fatalf("cli promotion: %s", body)
	}
	t.Logf("A236_PROMOTION_OK")
}
