// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedPrivilegedAccountImportA260: staged accounts are imported into a
// folder only after independent review. The import is requested, reviewers
// other than its requester approve the exact accounts and folder, and the
// requester applies it with the approval; before approval it is refused,
// and an account that changed since its review is refused. Importing grants
// nothing: the database's roles hash the same, no PAM target is registered
// and no session exists. A dismissed account leaves the staged list until a
// scan finds it changed. Another tenant sees none of it.
func TestServedPrivilegedAccountImportA260(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a260PostgresImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a260PostgresImage, err, out)
	}
	pgID, pgAddr := a201Container(t, "5432", "-e", "POSTGRES_PASSWORD=a260-import-admin", a260PostgresImage)
	a256AwaitLog(t, pgID, "PostgreSQL init process complete")
	psql := func(sql string) string {
		t.Helper()
		var out string
		var err error
		for i := 0; i < 30; i++ {
			if out, err = a201Exec(pgID, "psql", "-U", "postgres", "-tAc", sql); err == nil {
				return out
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: %v %s", sql, err, out)
		return ""
	}
	psql("CREATE ROLE app_admin SUPERUSER LOGIN")
	psql("CREATE ROLE etl LOGIN")
	psql("GRANT pg_read_all_data TO etl")
	psql("CREATE ROLE role_maker CREATEROLE LOGIN")
	roles := func() string {
		return psql("SELECT md5(string_agg(rolname || rolsuper || rolcreaterole || rolcreatedb || rolreplication || rolbypassrls || rolcanlogin || " +
			"coalesce(rolpassword, ''), ',' ORDER BY rolname)) || (SELECT md5(string_agg(roleid || ':' || member, ',' ORDER BY roleid, member)) " +
			"FROM pg_auth_members) FROM pg_authid")
	}

	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "a260i-pg", Type: "postgresql", Database: "postgres", Schema: "public", UsernamePrefix: "a260",
		AdminDSNRef:  writeServedCredentialFile(t, "a260i-pg-dsn", "postgres://postgres:a260-import-admin@"+pgAddr+"/postgres?sslmode=disable"),
		AllowedRoles: []string{"readonly"}, MaxTTL: "1h",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: registry.ForTenant(servedTestTenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a260-importer", "access:read", "access:targets.write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "a260-reviewer-1", "access:read", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "a260-reviewer-2", "access:read", "access:approve")
	key := func(what string) string { return "a260i-" + what + "-" + uuid.NewString()[:8] }

	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/access/discovery/sources/a260i-pg", requester, key("save"),
		map[string]any{"interval_seconds": 0}); status != http.StatusOK {
		t.Fatalf("save source = %d %s", status, body)
	}
	scan := func() {
		t.Helper()
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/sources/a260i-pg/runs", requester,
			key("scan"), nil); status != http.StatusCreated {
			t.Fatalf("scan = %d %s", status, body)
		}
	}
	staged := func(status string) map[string]a260Account {
		t.Helper()
		path := "/api/v1/access/discovery/accounts?provider_id=a260i-pg"
		if status != "" {
			path += "&status=" + status
		}
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, path, requester, nil)
		var page struct {
			Items []a260Account `json:"items"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &page) != nil {
			t.Fatalf("list staged = %d %s", code, body)
		}
		out := map[string]a260Account{}
		for _, a := range page.Items {
			out[a.Name] = a
		}
		return out
	}
	scan()
	accounts := staged("staged")
	for _, name := range []string{"app_admin", "etl", "role_maker", "postgres"} {
		if accounts[name].ID == "" {
			t.Fatalf("%s is not staged: %+v", name, accounts)
		}
	}

	type review struct {
		RequestID         string `json:"request_id"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		Status            string `json:"status"`
		RequiredApprovals int    `json:"required_approvals"`
		Accounts          int    `json:"accounts"`
	}
	request := func(folder, reason string, names ...string) (map[string]any, review) {
		t.Helper()
		var ids []string
		for _, n := range names {
			ids = append(ids, accounts[n].ID)
		}
		body := map[string]any{"request_id": uuid.NewString(), "account_ids": ids, "folder": folder, "reason": reason}
		status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/imports", requester, key("request"), body)
		var r review
		if status != http.StatusAccepted || json.Unmarshal(raw, &r) != nil || r.Status != "pending" || r.Accounts != len(names) {
			t.Fatalf("request import = %d %s", status, raw)
		}
		return body, r
	}
	approve := func(r review) {
		t.Helper()
		for i, reviewer := range []string{reviewerOne, reviewerTwo} {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals",
				reviewer, key("approve"), map[string]any{"intent_digest": r.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d = %d %s", i+1, status, body)
			}
		}
	}
	apply := func(body map[string]any, r review) (int, []byte) {
		t.Helper()
		body["approval_request_id"], body["intent_digest"] = r.ApprovalRequestID, r.IntentDigest
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/imports/"+r.RequestID+"/apply", requester, key("apply"), body)
	}

	// An import is reviewed before it applies, and its requester cannot
	// review it.
	targetsBefore := pamTargetCount(t, h)
	rolesBefore := roles()
	body, r := request("db-admins", "bring the orders database's administrators under review", "app_admin", "etl")
	if r.RequiredApprovals < 2 {
		t.Fatalf("an import needs %d approvals", r.RequiredApprovals)
	}
	if status, raw := apply(body, r); status == http.StatusOK {
		t.Fatalf("an unreviewed import applied: %s", raw)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+r.ApprovalRequestID+"/approvals", requester,
		key("self-approve"), map[string]any{"intent_digest": r.IntentDigest}); status == http.StatusOK {
		t.Fatal("the requester approved their own import")
	}
	approve(r)
	status, raw := apply(body, r)
	var applied struct {
		Items []struct {
			Name   string `json:"name"`
			Folder string `json:"folder"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &applied) != nil || len(applied.Items) != 2 {
		t.Fatalf("apply = %d %s", status, raw)
	}
	if status, raw := apply(body, r); status != http.StatusOK {
		t.Fatalf("a repeated apply = %d %s", status, raw)
	}
	code, listed := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/accounts?folder=db-admins", reviewerOne, nil)
	var folder struct {
		Items []struct {
			Name       string   `json:"name"`
			Privileges []string `json:"privileges"`
			ImportedBy string   `json:"imported_by"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(listed, &folder) != nil || len(folder.Items) != 2 {
		t.Fatalf("list the folder = %d %s", code, listed)
	}
	var names []string
	for _, a := range folder.Items {
		names = append(names, a.Name)
		if a.ImportedBy != "a260-importer" || len(a.Privileges) == 0 {
			t.Fatalf("imported account = %+v", a)
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "app_admin,etl" {
		t.Fatalf("the folder holds %v", names)
	}
	if got := staged("imported"); got["app_admin"].ID == "" || got["etl"].ID == "" {
		t.Fatalf("the imported accounts are not marked imported: %+v", got)
	}

	// Importing granted nothing.
	if after := roles(); after != rolesBefore {
		t.Fatalf("the import changed the database's roles: %s → %s", rolesBefore, after)
	}
	if after := pamTargetCount(t, h); after != targetsBefore {
		t.Fatalf("the import registered PAM targets: %d → %d", targetsBefore, after)
	}
	if code, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions", requester, nil); code != http.StatusOK ||
		strings.Contains(string(raw), `"id":`) {
		t.Fatalf("the import opened a session: %d %s", code, raw)
	}

	// An account that changed since its review is refused.
	body, r = request("db-admins", "the role maker too", "role_maker")
	approve(r)
	psql("ALTER ROLE role_maker CREATEDB")
	scan()
	if status, raw := apply(body, r); status == http.StatusOK || !strings.Contains(string(raw), "changed since its review") {
		t.Fatalf("an import whose account changed since its review = %d %s", status, raw)
	}

	// A dismissed account leaves the staged list until it changes.
	accounts = staged("staged")
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/accounts/"+accounts["role_maker"].ID+"/dismiss",
		requester, key("dismiss"), map[string]any{"reason": "a break-glass role the DBAs keep outside the vault"}); status != http.StatusOK ||
		!strings.Contains(string(raw), `"status":"dismissed"`) {
		t.Fatalf("dismiss = %d %s", status, raw)
	}
	if _, ok := staged("staged")["role_maker"]; ok {
		t.Fatal("a dismissed account is still staged")
	}
	psql("ALTER ROLE role_maker BYPASSRLS")
	scan()
	if staged("staged")["role_maker"].ID == "" {
		t.Fatal("a dismissed account a scan found changed was not staged again")
	}

	// Another tenant sees none of it and cannot apply this tenant's import.
	otherTenant := "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: otherTenant, Name: "A260 import foreign tenant"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, otherTenant, "a260-import-foreign", "access:read", "access:targets.write")
	code, raw = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/accounts", foreign, nil)
	var empty struct {
		Items []json.RawMessage `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &empty) != nil || len(empty.Items) != 0 {
		t.Fatalf("the other tenant listed imported accounts: %d %s", code, raw)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/discovery/accounts/"+accounts["postgres"].ID+"/dismiss",
		foreign, key("foreign-dismiss"), map[string]any{"reason": "not mine"}); status == http.StatusOK {
		t.Fatal("the other tenant dismissed this tenant's account")
	}
}

// pamTargetCount is the number of PAM targets the tenant has registered.
func pamTargetCount(t *testing.T, h *roleHarness) int {
	t.Helper()
	targets, err := h.store.ListPAMTargets(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	return len(targets)
}
