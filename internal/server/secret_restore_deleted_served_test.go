// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A236-L5 Done-when: a folder restore brings back the secrets of the folder
// deleted since the point in time that are still kept. db/password (two
// versions, deleted at version 2) and db/user (deleted at version 1) are
// planned as restore_deleted with the version they had then and the deleted
// version, without a value; db/new (created and deleted since) and app/key
// (outside the folder) are not. Applying the plan answers db/password at
// version 3 holding its first value, with version 2 back in its history, and
// db/user at version 2; neither is listed as deleted any more, app/key and
// db/new still are. A tombstone purged after the preview makes the plan stale.
func TestServedFolderRestoreBringsBackSecretsDeletedSinceA236L5(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DeletedSecretRetention = 24 * time.Hour
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "a236l5-admin", "access:write", "secrets:read", "secrets:write")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects", admin, "a236l5-project", map[string]any{
		"slug": "a236l5vault", "environments": []map[string]any{{"slug": "dev"}}}); status != http.StatusCreated {
		t.Fatalf("create project = %d %s", status, body)
	}
	write := func(method, path, key string, body map[string]any, want int) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, method, path, admin, key, body); status != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, status, raw, want)
		}
	}
	const p = "a236l5vault/dev/"
	write(http.MethodPost, "/api/v1/secrets/store", "a236l5-pw", map[string]any{"name": p + "db/password", "value": "pw-one-a236l5"}, http.StatusCreated)
	write(http.MethodPost, "/api/v1/secrets/store", "a236l5-user", map[string]any{"name": p + "db/user", "value": "user-one-a236l5"}, http.StatusCreated)
	write(http.MethodPost, "/api/v1/secrets/store", "a236l5-key", map[string]any{"name": p + "app/key", "value": "key-one-a236l5"}, http.StatusCreated)
	time.Sleep(20 * time.Millisecond)
	at := time.Now().UTC()
	time.Sleep(20 * time.Millisecond)
	write(http.MethodPut, "/api/v1/secrets/store/"+p+"db/password", "a236l5-pw-2", map[string]any{"value": "pw-two-a236l5"}, http.StatusOK)
	write(http.MethodDelete, "/api/v1/secrets/store/"+p+"db/password", "a236l5-pw-del", nil, http.StatusNoContent)
	write(http.MethodDelete, "/api/v1/secrets/store/"+p+"db/user", "a236l5-user-del", nil, http.StatusNoContent)
	write(http.MethodPost, "/api/v1/secrets/store", "a236l5-new", map[string]any{"name": p + "db/new", "value": "new-a236l5"}, http.StatusCreated)
	write(http.MethodDelete, "/api/v1/secrets/store/"+p+"db/new", "a236l5-new-del", nil, http.StatusNoContent)
	write(http.MethodDelete, "/api/v1/secrets/store/"+p+"app/key", "a236l5-key-del", nil, http.StatusNoContent)

	type planItem struct {
		Name           string     `json:"name"`
		CurrentVersion int        `json:"current_version"`
		RestoreVersion int        `json:"restore_version"`
		Action         string     `json:"action"`
		DeletedVersion int        `json:"deleted_version"`
		DeletedAt      *time.Time `json:"deleted_at"`
	}
	type plan struct {
		PlanDigest string     `json:"plan_digest"`
		Items      []planItem `json:"items"`
		Changes    int        `json:"changes"`
	}
	req := map[string]any{"environment": "dev", "folder": "db", "at": at.Format(time.RFC3339Nano)}
	preview := func() (plan, string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/projects/a236l5vault/restores/preview", admin, req)
		var out plan
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("restore preview = %d %s", status, body)
		}
		return out, string(body)
	}
	got, raw := preview()
	if strings.Contains(raw, "a236l5\"") || strings.Contains(raw, "-one-a236l5") || strings.Contains(raw, "-two-a236l5") {
		t.Fatalf("the restore plan carries a value: %s", raw)
	}
	want := map[string][3]int{p + "db/password": {1, 2, 0}, p + "db/user": {1, 1, 0}}
	if len(got.Items) != 2 || got.Changes != 2 {
		t.Fatalf("plan = %s; want db/password and db/user brought back, nothing else", raw)
	}
	for _, item := range got.Items {
		w, ok := want[item.Name]
		if !ok || item.Action != "restore_deleted" || item.RestoreVersion != w[0] || item.DeletedVersion != w[1] ||
			item.CurrentVersion != 0 || item.DeletedAt == nil {
			t.Fatalf("plan item %+v; want restore_deleted of %v (plan %s)", item, w, raw)
		}
	}

	req["plan_digest"] = got.PlanDigest
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/a236l5vault/restores", admin, "a236l5-apply", req)
	if status != http.StatusCreated {
		t.Fatalf("apply = %d %s", status, body)
	}
	var receipt struct {
		Items []struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &receipt) != nil || len(receipt.Items) != 2 {
		t.Fatalf("receipt = %s", body)
	}
	for _, item := range receipt.Items {
		if wantVersion := map[string]int{p + "db/password": 3, p + "db/user": 2}[item.Name]; item.Version != wantVersion {
			t.Fatalf("receipt item %+v; want version %d", item, wantVersion)
		}
	}
	if status, value, version := a236l4Value(t, h, admin, "/api/v1/secrets/store/"+p+"db/password"); status != http.StatusOK || value != "pw-one-a236l5" || version != 3 {
		t.Fatalf("db/password = %d %q v%d, want the first value at version 3", status, value, version)
	}
	if status, value, _ := a236l4Value(t, h, admin, "/api/v1/secrets/store/history/"+p+"db/password?version=2"); status != http.StatusOK || value != "pw-two-a236l5" {
		t.Fatalf("db/password history v2 = %d %q, want the second value back", status, value)
	}
	if status, value, version := a236l4Value(t, h, admin, "/api/v1/secrets/store/"+p+"db/user"); status != http.StatusOK || value != "user-one-a236l5" || version != 2 {
		t.Fatalf("db/user = %d %q v%d, want its value at version 2", status, value, version)
	}
	list, listed := a236l4Deleted(t, h, admin)
	for name, kept := range map[string]bool{p + "db/password": false, p + "db/user": false, p + "db/new": true, p + "app/key": true} {
		if _, _, _, _, ok := a236l4Listed(list, name); ok != kept {
			t.Fatalf("%s kept as deleted = %v, want %v (%s)", name, ok, kept, listed)
		}
	}

	// A tombstone purged after the preview makes the reviewed plan stale.
	write(http.MethodDelete, "/api/v1/secrets/store/"+p+"db/user", "a236l5-user-del-2", nil, http.StatusNoContent)
	stale, _ := preview()
	if len(stale.Items) == 0 {
		t.Fatalf("no plan to go stale: %+v", stale)
	}
	write(http.MethodDelete, "/api/v1/secrets/deleted/"+p+"db/user", "a236l5-user-purge", nil, http.StatusNoContent)
	req["plan_digest"] = stale.PlanDigest
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects/a236l5vault/restores", admin, "a236l5-stale", req); status != http.StatusConflict ||
		!strings.Contains(string(body), "plan_stale") {
		t.Fatalf("apply after the purge = %d %s, want 409 plan_stale", status, body)
	}
}
