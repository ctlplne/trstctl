// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A236-L3 Done-when: a promotion's receipt names the consumers to reload.
// Two consumers reported reading stage's db/password at version 1 (one
// injected, one verified), a third never reported it; promoting dev into
// stage writes version 2, and the receipt item for that secret names exactly
// the two consumers that hold version 1. A secret no consumer reported names
// none, and once a consumer reports the new version a later promotion of
// another change does not name it for an unchanged secret. A restore's
// receipt names them the same way.
func TestServedSecretPromotionReceiptNamesTheConsumersToReloadA236L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "reload-admin", "access:write", "secrets:read", "secrets:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects", admin, "a236l3-project", map[string]any{
		"slug": "reloads", "environments": []map[string]any{{"slug": "dev"}, {"slug": "stage"}}}); status != http.StatusCreated {
		t.Fatalf("create project = %d %s", status, body)
	}
	put := func(name, value string) {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", admin, "a236l3-put-"+name+"-"+value,
			map[string]any{"name": name, "value": value}); status != http.StatusCreated {
			t.Fatalf("put %s = %d %s", name, status, body)
		}
	}
	put("reloads/dev/db/password", "dev-pass-a236l3")
	put("reloads/dev/feature/flag", "on")
	put("reloads/stage/db/password", "stage-pass-a236l3")
	report := func(key, consumer, state, name string, version int) {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deliveries", admin, key, map[string]any{
			"consumer": consumer, "state": state, "secrets": []map[string]any{{"name": name, "version": version}}}); status != http.StatusOK {
			t.Fatalf("report %s = %d %s", consumer, status, body)
		}
	}
	report("a236l3-api", "reloads-api", "injected", "reloads/stage/db/password", 1)
	report("a236l3-worker", "reloads-worker", "verified", "reloads/stage/db/password", 1)

	promote := func(key string) map[string][]string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/reloads/promotions/preview", admin,
			map[string]any{"from": "dev", "to": "stage"})
		var plan struct {
			PlanDigest string `json:"plan_digest"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &plan) != nil {
			t.Fatalf("preview = %d %s", status, body)
		}
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/reloads/promotions", admin, key,
			map[string]any{"from": "dev", "to": "stage", "plan_digest": plan.PlanDigest})
		var receipt struct {
			Items []struct {
				Name    string   `json:"name"`
				Version int      `json:"version"`
				Reload  []string `json:"reload"`
			} `json:"items"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &receipt) != nil {
			t.Fatalf("apply = %d %s", status, body)
		}
		out := map[string][]string{}
		for _, item := range receipt.Items {
			out[item.Name] = item.Reload
		}
		return out
	}
	first := promote("a236l3-promote-1")
	if got := first["reloads/stage/db/password"]; !slices.Equal(got, []string{"reloads-api", "reloads-worker"}) {
		t.Fatalf("reload for db/password = %v; want the two consumers holding version 1 (receipt %v)", got, first)
	}
	if got, ok := first["reloads/stage/feature/flag"]; !ok || len(got) != 0 {
		t.Fatalf("a newly created secret no consumer reported names %v (present %v)", got, ok)
	}
	time.Sleep(20 * time.Millisecond)
	beforeSecond := time.Now().UTC()
	time.Sleep(20 * time.Millisecond)

	// The API reloads; the worker does not. A second change promotes only the flag.
	report("a236l3-api-v2", "reloads-api", "verified", "reloads/stage/db/password", 2)
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/reloads/dev/feature/flag", admin, "a236l3-rotate-flag",
		map[string]any{"value": "off"}); status != http.StatusOK {
		t.Fatalf("rotate the dev flag = %d %s", status, body)
	}
	report("a236l3-flag", "reloads-worker", "injected", "reloads/stage/feature/flag", 1)
	second := promote("a236l3-promote-2")
	if _, changed := second["reloads/stage/db/password"]; changed {
		t.Fatalf("an unchanged secret was promoted again: %v", second)
	}
	if got := second["reloads/stage/feature/flag"]; !slices.Equal(got, []string{"reloads-worker"}) {
		t.Fatalf("reload for feature/flag = %v; want the worker that holds version 1", got)
	}

	// Rolling stage's flag back to before the second promotion writes version
	// 3; the API reports version 2 and the worker still holds 1, so the
	// restore's receipt names both.
	report("a236l3-api-flag", "reloads-api", "verified", "reloads/stage/feature/flag", 2)
	restore := map[string]any{"environment": "stage", "folder": "feature", "at": beforeSecond.Format(time.RFC3339Nano)}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/reloads/restores/preview", admin, restore)
	var restorePlan struct {
		PlanDigest string `json:"plan_digest"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &restorePlan) != nil {
		t.Fatalf("restore preview = %d %s", status, body)
	}
	restore["plan_digest"] = restorePlan.PlanDigest
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/reloads/restores", admin, "a236l3-restore", restore)
	var restored struct {
		Items []struct {
			Name    string   `json:"name"`
			Version int      `json:"version"`
			Reload  []string `json:"reload"`
		} `json:"items"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &restored) != nil || len(restored.Items) != 1 {
		t.Fatalf("restore = %d %s", status, body)
	}
	if item := restored.Items[0]; item.Name != "reloads/stage/feature/flag" || item.Version != 3 ||
		!slices.Equal(item.Reload, []string{"reloads-api", "reloads-worker"}) {
		t.Fatalf("restore receipt item = %+v; want the flag at version 3 naming both consumers", item)
	}
}
