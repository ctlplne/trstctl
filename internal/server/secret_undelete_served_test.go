// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type a236l4DeletedList struct {
	Items []struct {
		Name       string    `json:"name"`
		Version    int       `json:"version"`
		Versions   int       `json:"versions"`
		DeletedAt  time.Time `json:"deleted_at"`
		PurgeAfter time.Time `json:"purge_after"`
	} `json:"items"`
}

func a236l4Deleted(t *testing.T, h *servedHarness, token string) (a236l4DeletedList, string) {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/deleted", token, nil)
	var list a236l4DeletedList
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("list deleted secrets = %d %s", status, body)
	}
	return list, string(body)
}

func a236l4Listed(list a236l4DeletedList, name string) (int, int, time.Time, time.Time, bool) {
	for _, item := range list.Items {
		if item.Name == name {
			return item.Version, item.Versions, item.DeletedAt, item.PurgeAfter, true
		}
	}
	return 0, 0, time.Time{}, time.Time{}, false
}

func a236l4Value(t *testing.T, h *servedHarness, token, path string) (int, string, int) {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, path, token, nil)
	var value struct {
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if status == http.StatusOK && json.Unmarshal(body, &value) != nil {
		t.Fatalf("decode %s: %s", path, body)
	}
	return status, value.Value, value.Version
}

// A236-L4 Done-when: a deleted secret is kept, sealed with its history, for
// the retention window and restored at the version it had. Deleting a
// two-version secret lists it (version 2, two versions, purge after the
// window, no value); restoring it answers version 2, reads the second value
// and the first from history, and an exact retry answers the same; the
// tombstone is gone. A live secret under the name refuses a restore (409). A
// purge removes the kept secret at once, and the retention sweep removes one
// kept past the window.
func TestServedDeletedSecretRestoresWithItsHistoryA236L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.DeletedSecretRetention = 24 * time.Hour
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "undelete-admin", "secrets:read", "secrets:write")
	const name = "a236l4/app/db-password"
	write := func(method, path, key string, body map[string]any, want int) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, method, path, admin, key, body); status != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, status, raw, want)
		}
	}
	write(http.MethodPost, "/api/v1/secrets/store", "a236l4-create", map[string]any{"name": name, "value": "first-a236l4-value"}, http.StatusCreated)
	write(http.MethodPut, "/api/v1/secrets/store/"+name, "a236l4-rotate", map[string]any{"value": "second-a236l4-value"}, http.StatusOK)
	write(http.MethodDelete, "/api/v1/secrets/store/"+name, "a236l4-delete", nil, http.StatusNoContent)
	if status, _, _ := a236l4Value(t, h, admin, "/api/v1/secrets/store/"+name); status != http.StatusNotFound {
		t.Fatalf("a deleted secret reads %d, want 404", status)
	}

	list, raw := a236l4Deleted(t, h, admin)
	version, versions, deletedAt, purgeAfter, ok := a236l4Listed(list, name)
	if !ok || version != 2 || versions != 2 || !purgeAfter.Equal(deletedAt.Add(24*time.Hour)) {
		t.Fatalf("deleted list = %s; want %s at version 2 with two versions, purged a day after deletion", raw, name)
	}
	if strings.Contains(raw, "a236l4-value") {
		t.Fatalf("the deleted list carries a value: %s", raw)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deleted/"+name, admin, "a236l4-restore", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"version":2`) {
		t.Fatalf("restore = %d %s, want 200 at version 2", status, body)
	}
	if again, retry := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deleted/"+name, admin, "a236l4-restore", nil); again != http.StatusOK || string(retry) != string(body) {
		t.Fatalf("exact retry = %d %s, want the first answer %s", again, retry, body)
	}
	if status, value, version := a236l4Value(t, h, admin, "/api/v1/secrets/store/"+name); status != http.StatusOK || value != "second-a236l4-value" || version != 2 {
		t.Fatalf("restored secret = %d %q v%d, want the second value at version 2", status, value, version)
	}
	if status, value, _ := a236l4Value(t, h, admin, "/api/v1/secrets/store/history/"+name+"?version=1"); status != http.StatusOK || value != "first-a236l4-value" {
		t.Fatalf("restored history version 1 = %d %q, want the first value", status, value)
	}
	if list, raw := a236l4Deleted(t, h, admin); func() bool { _, _, _, _, ok := a236l4Listed(list, name); return ok }() {
		t.Fatalf("a restored secret is still listed as deleted: %s", raw)
	}
	if _, _, err := h.store.GetDeletedSecret(context.Background(), h.tenant, name); err != store.ErrSecretNotFound {
		t.Fatalf("the tombstone outlived its restore: err=%v", err)
	}
	// The restored secret holds the name: another restore is a conflict.
	write(http.MethodPost, "/api/v1/secrets/deleted/"+name, "a236l4-restore-again", nil, http.StatusConflict)

	// A live secret under the name refuses the restore of the deleted one.
	write(http.MethodDelete, "/api/v1/secrets/store/"+name, "a236l4-delete-2", nil, http.StatusNoContent)
	write(http.MethodPost, "/api/v1/secrets/store", "a236l4-recreate", map[string]any{"name": name, "value": "third-a236l4-value"}, http.StatusCreated)
	write(http.MethodPost, "/api/v1/secrets/deleted/"+name, "a236l4-restore-over-live", nil, http.StatusConflict)
	if status, value, version := a236l4Value(t, h, admin, "/api/v1/secrets/store/"+name); status != http.StatusOK || value != "third-a236l4-value" || version != 1 {
		t.Fatalf("the live secret = %d %q v%d after a refused restore", status, value, version)
	}

	// A purge removes the kept secret at once; a second purge finds none.
	write(http.MethodDelete, "/api/v1/secrets/store/"+name, "a236l4-delete-3", nil, http.StatusNoContent)
	write(http.MethodDelete, "/api/v1/secrets/deleted/"+name, "a236l4-purge", nil, http.StatusNoContent)
	if list, raw := a236l4Deleted(t, h, admin); func() bool { _, _, _, _, ok := a236l4Listed(list, name); return ok }() {
		t.Fatalf("a purged secret is still listed: %s", raw)
	}
	write(http.MethodPost, "/api/v1/secrets/deleted/"+name, "a236l4-restore-purged", nil, http.StatusNotFound)
	write(http.MethodDelete, "/api/v1/secrets/deleted/"+name, "a236l4-purge-again", nil, http.StatusNotFound)

	// The retention sweep removes a deleted secret kept past the window.
	const swept = "a236l4/app/api-token"
	write(http.MethodPost, "/api/v1/secrets/store", "a236l4-create-swept", map[string]any{"name": swept, "value": "swept-a236l4-value"}, http.StatusCreated)
	write(http.MethodDelete, "/api/v1/secrets/store/"+swept, "a236l4-delete-swept", nil, http.StatusNoContent)
	if n, err := h.srv.PurgeDeletedSecretsOnce(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("a sweep within the window: %d %v", n, err)
	}
	if list, raw := a236l4Deleted(t, h, admin); func() bool { _, _, _, _, ok := a236l4Listed(list, swept); return !ok }() {
		t.Fatalf("the sweep removed a deleted secret inside the window: %s", raw)
	}
	if n, err := h.srv.PurgeDeletedSecretsOnce(context.Background(), time.Now().Add(25*time.Hour)); err != nil || n < 1 {
		t.Fatalf("a sweep past the window purged %d err=%v", n, err)
	}
	if list, raw := a236l4Deleted(t, h, admin); func() bool { _, _, _, _, ok := a236l4Listed(list, swept); return ok }() {
		t.Fatalf("a deleted secret past the window is still kept: %s", raw)
	}
	if h.logContains(t, "swept-a236l4-value") || h.logContains(t, "second-a236l4-value") {
		t.Fatal("the event log carries a secret value (AN-8)")
	}
}

// A236-L4: with no retention a deletion keeps nothing — the value and its
// history are gone when the call returns, and there is nothing to restore.
func TestServedDeletedSecretWithoutRetentionKeepsNothingA236L4(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "undelete-none", "secrets:read", "secrets:write")
	const name = "a236l4-none/app/key"
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", admin, "a236l4-none-create",
		map[string]any{"name": name, "value": "kept-nowhere-a236l4"}); status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, admin, "a236l4-none-delete", nil); status != http.StatusNoContent {
		t.Fatalf("delete = %d %s", status, body)
	}
	if _, _, err := h.store.GetDeletedSecret(context.Background(), h.tenant, name); err != store.ErrSecretNotFound {
		t.Fatalf("a deletion without retention kept a tombstone: err=%v", err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deleted/"+name, admin, "a236l4-none-restore", nil); status != http.StatusNotFound {
		t.Fatalf("restore without retention = %d %s, want 404", status, body)
	}
}

// A236-L4: under dual control a restore is an exact, one-shot approval like
// every other secret change: the first request names the approval (from the
// deleted version to that version, at that deletion), the requester cannot
// approve it, and two approvers' decision lets the same request restore the
// secret once.
func TestServedDeletedSecretRestoreTakesDualControlA236L4(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.RequireApproval = true
		d.RequiredApprovals = 2
		d.DeletedSecretRetention = 24 * time.Hour
	})
	registerServedTenant(t, h, "served dual-control deleted-secret tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a236l4-alice", "secrets:read", "secrets:write")
	approverA := seedScopedTokenSubject(t, h.store, h.tenant, "a236l4-bob", "secrets:write")
	approverB := seedScopedTokenSubject(t, h.store, h.tenant, "a236l4-carol", "secrets:write")
	ctx := context.Background()
	const name = "a236l4-dual/db/password"
	pending := func(action string) store.OperationApprovalRequest {
		t.Helper()
		rows, err := h.store.ListOperationApprovals(ctx, h.tenant, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ResourceID == "secret:"+name && row.Action == action && row.Status == store.ApprovalStatusPending {
				return row
			}
		}
		t.Fatalf("no pending %s approval for %s: %+v", action, name, rows)
		return store.OperationApprovalRequest{}
	}
	approve := func(token, key string, approval store.OperationApprovalRequest, want int) {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store/approvals/"+name, token, key,
			map[string]any{"action": approval.Action, "request_id": approval.ID, "intent_digest": approval.IntentDigest}); status != want {
			t.Fatalf("approve %s = %d %s, want %d", approval.Action, status, body, want)
		}
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", requester, "a236l4-dual-create",
		map[string]any{"name": name, "value": "dual-a236l4-value"}); status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, requester, "a236l4-dual-delete", nil); status != http.StatusForbidden {
		t.Fatalf("delete before approval = %d %s, want 403", status, body)
	}
	deletion := pending("delete")
	approve(approverA, "a236l4-dual-delete-bob", deletion, http.StatusOK)
	approve(approverB, "a236l4-dual-delete-carol", deletion, http.StatusOK)
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+name, requester, "a236l4-dual-delete", nil); status != http.StatusNoContent {
		t.Fatalf("approved delete = %d %s", status, body)
	}

	const restoreKey = "a236l4-dual-restore"
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deleted/"+name, requester, restoreKey, nil); status != http.StatusForbidden ||
		!strings.Contains(string(body), "approval_required") {
		t.Fatalf("restore before approval = %d %s, want 403 naming the approval", status, body)
	}
	restore := pending("undelete")
	if restore.FromState != "deleted:version:1" || !strings.HasPrefix(restore.ToState, "version:1:undelete:") || restore.TargetVersion != 1 {
		t.Fatalf("restore approval is not exact: %+v", restore)
	}
	if status, _, _ := a236l4Value(t, h, requester, "/api/v1/secrets/store/"+name); status != http.StatusNotFound {
		t.Fatalf("an unapproved restore brought the secret back: %d", status)
	}
	approve(requester, "a236l4-dual-self", restore, http.StatusForbidden)
	approve(approverA, "a236l4-dual-restore-bob", restore, http.StatusOK)
	approve(approverB, "a236l4-dual-restore-carol", restore, http.StatusOK)
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deleted/"+name, requester, restoreKey, nil); status != http.StatusOK {
		t.Fatalf("approved restore = %d %s", status, body)
	}
	if status, value, version := a236l4Value(t, h, requester, "/api/v1/secrets/store/"+name); status != http.StatusOK || value != "dual-a236l4-value" || version != 1 {
		t.Fatalf("restored secret = %d %q v%d", status, value, version)
	}
	spent, err := h.store.GetOperationApproval(ctx, h.tenant, restore.ID)
	if err != nil || spent.Status != store.ApprovalStatusConsumed || spent.ConsumedEventID == "" {
		t.Fatalf("the restore's approval was not consumed with it: %+v err=%v", spent, err)
	}
}
