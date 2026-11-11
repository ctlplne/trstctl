// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A236-L2: a secret an environment promotion creates takes its source's owner.
// The reviewed plan names the owner each created secret will take, the
// created secret carries it, a secret whose source has no owner stays
// without one, and a promotion that updates an existing target keeps that
// target's own owner.
func TestServedPromotedSecretTakesItsSourceOwnerA236L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a236l2-admin", "access:write", "secrets:read", "secrets:write", "owners:write", "owners:read")
	ctx := t.Context()
	const project = "a236l2-billing"
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects", admin, "a236l2-project", map[string]any{
		"slug": project, "environments": []map[string]any{{"slug": "dev"}, {"slug": "stage"}},
	}); status != http.StatusCreated {
		t.Fatalf("create the project: HTTP %d %s", status, body)
	}
	owner := func(key, name string) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", admin, key, map[string]any{"kind": "team", "name": name})
		var created struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
			t.Fatalf("create owner %s: HTTP %d %s", name, status, body)
		}
		return created.ID
	}
	payments := owner("a236l2-owner-payments", "a236l2 payments team")
	platform := owner("a236l2-owner-platform", "a236l2 platform team")
	put := func(name, value, ownerID string) {
		t.Helper()
		body := map[string]any{"name": name, "value": value}
		if ownerID != "" {
			body["owner_id"] = ownerID
		}
		if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", admin, "a236l2-put-"+name, body); status != http.StatusCreated {
			t.Fatalf("put %s: HTTP %d %s", name, status, out)
		}
	}
	put(project+"/dev/db/password", "a236l2-dev-pass", payments)
	put(project+"/dev/db/user", "a236l2-dev-user", "")
	put(project+"/dev/api/key", "a236l2-dev-key", payments)
	put(project+"/stage/api/key", "a236l2-stage-key", platform)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/"+project+"/promotions/preview", admin, map[string]any{"from": "dev", "to": "stage"})
	var plan struct {
		PlanDigest string `json:"plan_digest"`
		Items      []struct {
			Key       string `json:"key"`
			Action    string `json:"action"`
			OwnerID   string `json:"owner_id"`
			OwnerName string `json:"owner_name"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &plan) != nil {
		t.Fatalf("preview: HTTP %d %s", status, body)
	}
	planned := map[string][3]string{}
	for _, item := range plan.Items {
		planned[item.Key] = [3]string{item.Action, item.OwnerID, item.OwnerName}
	}
	if got := planned["db/password"]; got != [3]string{"create", payments, "a236l2 payments team"} {
		t.Errorf("the plan for the owned created secret = %v", got)
	}
	if got := planned["db/user"]; got != [3]string{"create", "", ""} {
		t.Errorf("the plan for the ownerless created secret = %v", got)
	}
	if got := planned["api/key"]; got != [3]string{"update", "", ""} {
		t.Errorf("the plan for the updated secret = %v", got)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/"+project+"/promotions", admin, "a236l2-apply",
		map[string]any{"from": "dev", "to": "stage", "plan_digest": plan.PlanDigest}); status != http.StatusCreated {
		t.Fatalf("apply: HTTP %d %s", status, body)
	}

	ownerOf := func(name string) string {
		t.Helper()
		s, err := h.store.GetSecret(ctx, h.tenant, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return s.OwnerID
	}
	if got := ownerOf(project + "/stage/db/password"); got != payments {
		t.Fatalf("the promoted secret's owner = %q, want its source's %q", got, payments)
	}
	if got := ownerOf(project + "/stage/db/user"); got != "" {
		t.Fatalf("a secret promoted from an ownerless source has owner %q", got)
	}
	if got := ownerOf(project + "/stage/api/key"); got != platform {
		t.Fatalf("an updated target's owner = %q, want its own %q", got, platform)
	}
}
