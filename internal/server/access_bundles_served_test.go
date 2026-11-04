// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type a251Via struct {
	GrantID    string `json:"grant_id"`
	BundleID   string `json:"bundle_id"`
	BundleName string `json:"bundle_name"`
}

type a251Authority struct {
	Principal   string `json:"principal"`
	Permissions []struct {
		Permission string    `json:"permission"`
		Via        []a251Via `json:"via"`
	} `json:"permissions"`
	Grants []struct {
		ID string `json:"id"`
	} `json:"grants"`
	Runs []struct {
		ID string `json:"id"`
	} `json:"runs"`
	Bounds struct {
		Revocation string `json:"revocation"`
		Outage     string `json:"outage"`
		Lasting    string `json:"lasting"`
	} `json:"bounds"`
}

func (a a251Authority) held() map[string][]string {
	out := map[string][]string{}
	for _, p := range a.Permissions {
		for _, v := range p.Via {
			out[p.Permission] = append(out[p.Permission], v.BundleName)
		}
	}
	return out
}

type a251Run struct {
	ID          string   `json:"id"`
	Principal   string   `json:"principal"`
	BundleNames []string `json:"bundle_names"`
	Permissions []string `json:"permissions"`
	Effective   []string `json:"effective"`
	Status      string   `json:"status"`
	IssuedBy    string   `json:"issued_by"`
	Chain       []struct {
		Step  string `json:"step"`
		Actor string `json:"actor"`
	} `json:"chain"`
}

type a251RunIssued struct {
	Run    a251Run `json:"run"`
	Token  string  `json:"token"`
	Launch struct {
		TokenEnv    string `json:"token_env"`
		CustomAgent string `json:"custom_agent"`
		CI          string `json:"ci"`
		MCPServer   string `json:"mcp_server"`
	} `json:"launch"`
}

type a251Harness struct {
	t *testing.T
	h *servedHarness
}

func (x a251Harness) call(method, path, token, key string, body any, want int) []byte {
	x.t.Helper()
	code, out := doBearer(x.t, x.h.ts, method, path, token, key, body)
	if code != want {
		x.t.Fatalf("%s %s = %d, want %d; body=%s", method, path, code, want, out)
	}
	return out
}

func (x a251Harness) bundle(token, key, name string, perms ...string) string {
	x.t.Helper()
	var got struct {
		ID string `json:"id"`
	}
	raw := x.call(http.MethodPost, "/api/v1/access/bundles", token, key, map[string]any{
		"name": name, "permissions": perms, "audiences": []string{"ci", "custom_agent"}, "max_run_ttl_seconds": 1800,
	}, http.StatusCreated)
	if err := json.Unmarshal(raw, &got); err != nil || got.ID == "" {
		x.t.Fatalf("create bundle %s: %v %s", name, err, raw)
	}
	return got.ID
}

func (x a251Harness) grant(token, key, bundleID, principalType, principal string) (string, a251Authority) {
	x.t.Helper()
	var got struct {
		Grant struct {
			ID   string `json:"id"`
			Live bool   `json:"live"`
		} `json:"grant"`
		Authority a251Authority `json:"authority"`
	}
	raw := x.call(http.MethodPost, "/api/v1/access/bundles/"+bundleID+"/grants", token, key,
		map[string]any{"principal_type": principalType, "principal": principal}, http.StatusCreated)
	if err := json.Unmarshal(raw, &got); err != nil || got.Grant.ID == "" || !got.Grant.Live {
		x.t.Fatalf("grant %s to %s: %v %s", bundleID, principal, err, raw)
	}
	return got.Grant.ID, got.Authority
}

func (x a251Harness) ungrant(token, key, bundleID, grantID string) a251Authority {
	x.t.Helper()
	var got struct {
		Grant struct {
			RemovedAt *time.Time `json:"removed_at"`
			Live      bool       `json:"live"`
		} `json:"grant"`
		Authority a251Authority `json:"authority"`
	}
	raw := x.call(http.MethodDelete, "/api/v1/access/bundles/"+bundleID+"/grants/"+grantID+"?reason=rotated", token, key, nil, http.StatusOK)
	if err := json.Unmarshal(raw, &got); err != nil || got.Grant.RemovedAt == nil || got.Grant.Live {
		x.t.Fatalf("ungrant %s: %v %s", grantID, err, raw)
	}
	return got.Authority
}

func (x a251Harness) authority(token, principal string) a251Authority {
	x.t.Helper()
	var got a251Authority
	raw := x.call(http.MethodGet, "/api/v1/access/authority?principal="+url.QueryEscape(principal), token, "", nil, http.StatusOK)
	if err := json.Unmarshal(raw, &got); err != nil {
		x.t.Fatal(err)
	}
	return got
}

func (x a251Harness) run(token, key string, body map[string]any) a251RunIssued {
	x.t.Helper()
	var got a251RunIssued
	raw := x.call(http.MethodPost, "/api/v1/access/runs", token, key, body, http.StatusCreated)
	if err := json.Unmarshal(raw, &got); err != nil || !strings.HasPrefix(got.Token, auth.TokenPrefix) {
		x.t.Fatalf("issue run: %v (token prefix %q, %d response bytes)", err, got.Token[:min(len(got.Token), 5)], len(raw))
	}
	return got
}

func (x a251Harness) status(method, path, token string) int {
	x.t.Helper()
	code, _ := doBearer(x.t, x.h.ts, method, path, token, "", nil)
	return code
}

// A251 Done when, part 1: removing one of several grants computes the
// remaining access correctly — on the authority view and on a live run token,
// at its very next request.
func TestServedAccessBundleGrantRemovalA251(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "bundle-admin", "access:write", "access:read", "certs:read", "owners:read")
	machine := seedScopedTokenSubject(t, h.store, h.tenant, "ci:deploy", "access:bundle.run")

	full := x.bundle(admin, "a251-create-full", "deploy-full", "owners:read", "certs:read")
	owners := x.bundle(admin, "a251-create-owners", "deploy-owners", "owners:read")
	gFull, after := x.grant(admin, "a251-grant-full", full, "machine", "ci:deploy")
	if held := after.held(); !slices.Equal(held["certs:read"], []string{"deploy-full"}) || len(held) != 2 {
		t.Fatalf("authority after the first grant = %+v", held)
	}
	gOwners, after := x.grant(admin, "a251-grant-owners", owners, "machine", "ci:deploy")
	if held := after.held(); len(held["owners:read"]) != 2 || len(held["certs:read"]) != 1 {
		t.Fatalf("authority after the second grant = %+v", held)
	}

	issued := x.run(machine, "a251-run-1", map[string]any{"bundle_ids": []string{full, owners}, "ttl_seconds": 600, "label": "deploy #1"})
	if issued.Run.Status != "active" || !slices.Equal(issued.Run.Effective, []string{"certs:read", "owners:read"}) ||
		issued.Run.IssuedBy != "ci:deploy" || len(issued.Run.Chain) != 5 {
		t.Fatalf("issued run = %+v", issued.Run)
	}
	if issued.Launch.TokenEnv != "TRSTCTL_TOKEN" {
		t.Fatalf("launch = %+v", issued.Launch)
	}
	for _, line := range []string{issued.Launch.CustomAgent, issued.Launch.CI, issued.Launch.MCPServer} {
		if line == "" || strings.Contains(line, issued.Token) {
			t.Fatalf("a launch line is empty or carries the token: %q", line)
		}
	}
	runToken := issued.Token
	if code := x.status(http.MethodGet, "/api/v1/certificates", runToken); code != http.StatusOK {
		t.Fatalf("run reads certificates = %d", code)
	}
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusOK {
		t.Fatalf("run reads owners = %d", code)
	}
	// The machine's own credential holds only access:bundle.run.
	if code := x.status(http.MethodGet, "/api/v1/certificates", machine); code != http.StatusForbidden {
		t.Fatalf("machine token reads certificates = %d, want 403", code)
	}

	// Remove one of the two grants: owners:read survives through the other.
	after = x.ungrant(admin, "a251-ungrant-full", full, gFull)
	if held := after.held(); !slices.Equal(held["owners:read"], []string{"deploy-owners"}) || len(held) != 1 {
		t.Fatalf("authority after removing deploy-full = %+v", held)
	}
	if code := x.status(http.MethodGet, "/api/v1/certificates", runToken); code != http.StatusForbidden {
		t.Fatalf("run reads certificates after its grant was removed = %d, want 403", code)
	}
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusOK {
		t.Fatalf("run reads owners through the remaining grant = %d, want 200", code)
	}
	var runs struct {
		Items []a251Run `json:"items"`
	}
	if err := json.Unmarshal(x.call(http.MethodGet, "/api/v1/access/runs?principal=ci%3Adeploy", admin, "", nil, http.StatusOK), &runs); err != nil ||
		len(runs.Items) != 1 || !slices.Equal(runs.Items[0].Effective, []string{"owners:read"}) || runs.Items[0].Status != "active" {
		t.Fatalf("runs after one removal = %+v, %v", runs, err)
	}

	// Remove the last grant: the run holds nothing and is refused outright.
	after = x.ungrant(admin, "a251-ungrant-owners", owners, gOwners)
	if len(after.Permissions) != 0 || len(after.Grants) != 0 || len(after.Runs) != 0 {
		t.Fatalf("authority after removing both = %+v", after)
	}
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusUnauthorized {
		t.Fatalf("run with no grants left = %d, want 401", code)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/runs", machine, "a251-run-2",
		map[string]any{"bundle_ids": []string{owners}}); code != http.StatusForbidden || !bytes.Contains(body, []byte("no live grant")) {
		t.Fatalf("run without a grant = %d %s, want 403", code, body)
	}
	// Removing a removed grant changes nothing.
	x.ungrant(admin, "a251-ungrant-owners-again", owners, gOwners)
}

// A251 Done when, part 2: a deleted bundle can't come back — not through its
// live run, not by replaying the requests that made it, not by editing it, and
// not by re-using its name.
func TestServedAccessBundleDeletedCannotReturnA251(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "bundle-admin", "access:write", "access:read", "owners:read")
	mcp := seedScopedTokenSubject(t, h.store, h.tenant, "mcp:docs", "access:bundle.run")
	createBody := map[string]any{"name": "mcp-readers", "permissions": []string{"owners:read"}, "audiences": []string{"mcp_server"}, "max_run_ttl_seconds": 900}
	created := x.call(http.MethodPost, "/api/v1/access/bundles", admin, "a251-create-mcp", createBody, http.StatusCreated)
	var bundle struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created, &bundle); err != nil {
		t.Fatal(err)
	}
	grantBody := map[string]any{"principal_type": "machine", "principal": "mcp:docs"}
	x.call(http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "a251-grant-mcp", grantBody, http.StatusCreated)
	runToken := x.run(mcp, "a251-run-mcp", map[string]any{"bundle_ids": []string{bundle.ID}}).Token
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusOK {
		t.Fatalf("run before delete = %d", code)
	}

	var deleted struct {
		Deleted        bool `json:"deleted"`
		GrantsAffected int  `json:"grants_affected"`
		RunsAffected   int  `json:"runs_affected"`
	}
	if err := json.Unmarshal(x.call(http.MethodDelete, "/api/v1/access/bundles/"+bundle.ID, admin, "a251-delete-mcp", nil, http.StatusOK), &deleted); err != nil ||
		!deleted.Deleted || deleted.GrantsAffected != 1 || deleted.RunsAffected != 1 {
		t.Fatalf("delete = %+v %v", deleted, err)
	}
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusUnauthorized {
		t.Fatalf("run after its bundle was deleted = %d, want 401", code)
	}

	// Replays return what was recorded and change nothing.
	if replay := x.call(http.MethodPost, "/api/v1/access/bundles", admin, "a251-create-mcp", createBody, http.StatusCreated); !bytes.Equal(replay, created) {
		t.Fatalf("create replay differs from the recorded response:\n%s\n%s", replay, created)
	}
	x.call(http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "a251-grant-mcp", grantBody, http.StatusCreated)
	x.call(http.MethodGet, "/api/v1/access/bundles/"+bundle.ID, admin, "", nil, http.StatusNotFound)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(x.call(http.MethodGet, "/api/v1/access/bundles", admin, "", nil, http.StatusOK), &list); err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Items { // served tests share a tenant: look for this bundle only
		if item.ID == bundle.ID {
			t.Fatalf("the deleted bundle is listed after the replays: %+v", list)
		}
	}
	if got := x.authority(admin, "mcp:docs"); len(got.Permissions) != 0 || len(got.Grants) != 0 {
		t.Fatalf("authority after delete and replays = %+v", got)
	}
	// Nothing new reaches it.
	x.call(http.MethodPost, "/api/v1/access/bundles/"+bundle.ID+"/grants", admin, "a251-grant-mcp-2", grantBody, http.StatusNotFound)
	x.call(http.MethodPut, "/api/v1/access/bundles/"+bundle.ID, admin, "a251-edit-mcp",
		map[string]any{"name": "mcp-readers", "permissions": []string{"owners:read"}, "revision": bundle.Revision}, http.StatusNotFound)
	x.call(http.MethodPost, "/api/v1/access/runs", mcp, "a251-run-mcp-2", map[string]any{"bundle_ids": []string{bundle.ID}}, http.StatusNotFound)
	x.call(http.MethodDelete, "/api/v1/access/bundles/"+bundle.ID, admin, "a251-delete-mcp-2", nil, http.StatusNotFound)

	// The name may be used again, by a different bundle the old grant never reaches.
	again := x.bundle(admin, "a251-create-mcp-again", "mcp-readers", "owners:read")
	if again == bundle.ID {
		t.Fatal("re-creating the name returned the deleted bundle")
	}
	if got := x.authority(admin, "mcp:docs"); len(got.Permissions) != 0 {
		t.Fatalf("the old grant reaches the new bundle: %+v", got)
	}
	if code := x.status(http.MethodGet, "/api/v1/owners", runToken); code != http.StatusUnauthorized {
		t.Fatalf("old run after the name was re-used = %d, want 401", code)
	}

	activity, err := h.store.ListAccessBundleActivity(t.Context(), h.tenant, store.AccessBundleActivityFilter{BundleID: bundle.ID, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, a := range activity {
		if a.Action != "run_used" { // uses are recorded off the request path
			actions = append(actions, a.Action)
		}
	}
	if !slices.Equal(actions, []string{"deleted", "run_issued", "granted", "saved"}) {
		t.Fatalf("activity = %v", actions)
	}
}

// A251: nobody hands an agent more than they hold, a bundle never carries
// authority over access, a run never mints a run, and offboarding a member
// stops their runs on the next request.
func TestServedAccessBundleAttenuationA251(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "bundle-admin", "access:write", "access:read", "access:bundle.run", "certs:read", "owners:read")
	narrow := seedScopedTokenSubject(t, h.store, h.tenant, "narrow-admin", "access:write", "access:read")
	machine := seedScopedTokenSubject(t, h.store, h.tenant, "ci:build", "access:bundle.run")
	tenantAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "tenant-admin", "*")

	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles", narrow, "a251-narrow",
		map[string]any{"name": "too-much", "permissions": []string{"certs:read"}}); code != http.StatusForbidden || !bytes.Contains(body, []byte("do not hold")) {
		t.Fatalf("bundle beyond its author = %d %s", code, body)
	}
	for i, perm := range []string{"*", "access:write", "access:role.assign", "access:bundle.run"} {
		if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles", tenantAdmin, "a251-refused-"+string(rune('a'+i)),
			map[string]any{"name": "refused-" + string(rune('a'+i)), "permissions": []string{perm}}); code != http.StatusUnprocessableEntity {
			t.Fatalf("bundle carrying %s = %d %s, want 422", perm, code, body)
		}
	}
	certs := x.bundle(admin, "a251-create-certs", "cert-readers", "certs:read")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles/"+certs+"/grants", narrow, "a251-narrow-grant",
		map[string]any{"principal_type": "machine", "principal": "ci:build"}); code != http.StatusForbidden {
		t.Fatalf("grant beyond its granter = %d %s, want 403", code, body)
	}
	x.grant(admin, "a251-grant-certs", certs, "machine", "ci:build")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles/"+certs+"/grants", admin, "a251-grant-certs-twice",
		map[string]any{"principal_type": "machine", "principal": "ci:build"}); code != http.StatusConflict {
		t.Fatalf("second live grant = %d %s, want 409", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/runs", machine, "a251-ttl",
		map[string]any{"bundle_ids": []string{certs}, "ttl_seconds": 7200}); code != http.StatusUnprocessableEntity {
		t.Fatalf("run beyond the bundle's ceiling = %d %s, want 422", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/runs", machine, "a251-other",
		map[string]any{"principal": "ci:other", "bundle_ids": []string{certs}}); code != http.StatusForbidden {
		t.Fatalf("machine minting for another principal = %d %s, want 403", code, body)
	}
	issued := x.run(admin, "a251-admin-mints", map[string]any{"principal": "ci:build", "bundle_ids": []string{certs}, "ttl_seconds": 120})
	if issued.Run.Principal != "ci:build" || issued.Run.IssuedBy != "bundle-admin" {
		t.Fatalf("operator-minted run = %+v", issued.Run)
	}
	if code := x.status(http.MethodPost, "/api/v1/access/runs", issued.Token); code != http.StatusForbidden {
		t.Fatalf("a run minting a run = %d, want 403", code)
	}
	// Revoking: the principal's own run, or anyone's with access:write.
	var revoked a251Run
	if err := json.Unmarshal(x.call(http.MethodPost, "/api/v1/access/runs/"+issued.Run.ID+"/revoke", machine, "a251-revoke", nil, http.StatusOK), &revoked); err != nil ||
		revoked.Status != "revoked" || len(revoked.Effective) != 0 {
		t.Fatalf("revoke = %+v %v", revoked, err)
	}
	if code := x.status(http.MethodGet, "/api/v1/certificates", issued.Token); code != http.StatusUnauthorized {
		t.Fatalf("revoked run = %d, want 401", code)
	}

	// A user grant lives only while its member is active.
	const member = "dev@payments.example"
	x.call(http.MethodPut, "/api/v1/access/members/"+url.PathEscape(member), tenantAdmin, "a251-member",
		map[string]any{"display_name": "Dev", "roles": []string{"viewer"}, "source": "manual"}, http.StatusOK)
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/bundles/"+certs+"/grants", admin, "a251-grant-ghost",
		map[string]any{"principal_type": "user", "principal": "nobody@payments.example"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("user grant to a non-member = %d %s, want 422", code, body)
	}
	x.grant(admin, "a251-grant-user", certs, "user", member)
	userToken := seedScopedTokenSubject(t, h.store, h.tenant, member, "access:bundle.run")
	userRun := x.run(userToken, "a251-user-run", map[string]any{"bundle_ids": []string{certs}})
	if code := x.status(http.MethodGet, "/api/v1/certificates", userRun.Token); code != http.StatusOK {
		t.Fatalf("user's run = %d", code)
	}
	x.call(http.MethodPost, "/api/v1/access/members/"+url.PathEscape(member)+"/offboard", tenantAdmin, "a251-offboard",
		map[string]string{"reason": "left the team"}, http.StatusOK)
	if code := x.status(http.MethodGet, "/api/v1/certificates", userRun.Token); code != http.StatusUnauthorized {
		t.Fatalf("offboarded member's run = %d, want 401", code)
	}
	if got := x.authority(admin, member); len(got.Permissions) != 0 || len(got.Grants) != 0 {
		t.Fatalf("offboarded member's authority = %+v", got)
	}
	if got := x.authority(admin, "ci:build"); !strings.Contains(got.Bounds.Revocation, "next request") || got.Bounds.Outage == "" || got.Bounds.Lasting == "" {
		t.Fatalf("authority bounds = %+v", got.Bounds)
	}
}

// A251 Done when, part 3: activity is searchable, pages without loss, and its
// export carries metadata only — no token, no token hash, no Authorization
// value and no request body, by default and by construction.
func TestServedAccessActivityExportA251(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "bundle-admin", "access:write", "access:read", "owners:read", "certs:read")
	machine := seedScopedTokenSubject(t, h.store, h.tenant, "ci:export", "access:bundle.run")
	bundleID := x.bundle(admin, "a251-export-bundle", "export-readers", "owners:read", "certs:read")
	x.grant(admin, "a251-export-grant", bundleID, "machine", "ci:export")
	issued := x.run(machine, "a251-export-run", map[string]any{"bundle_ids": []string{bundleID}, "label": "job 77"})
	for _, path := range []string{"/api/v1/owners?limit=5", "/api/v1/owners?limit=5", "/api/v1/certificates"} {
		if code := x.status(http.MethodGet, path, issued.Token); code != http.StatusOK {
			t.Fatalf("run reads %s = %d", path, code)
		}
	}
	const marker = "a251-request-body-marker"
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", issued.Token, "a251-export-write",
		map[string]any{"name": marker, "kind": "team"}); code != http.StatusForbidden {
		t.Fatalf("run writes an owner = %d, want 403", code)
	}
	if err := h.srv.DrainCredentialUsage(t.Context()); err != nil {
		t.Fatal(err)
	}
	x.call(http.MethodPost, "/api/v1/access/runs/"+issued.Run.ID+"/revoke", machine, "a251-export-revoke", nil, http.StatusOK)

	type row struct {
		Action string `json:"action"`
		RunID  string `json:"run_id"`
		Detail string `json:"detail"`
	}
	var page struct {
		Items      []row  `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	var all []row
	path := "/api/v1/access/activity?principal=ci%3Aexport&limit=2"
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("activity paging does not end")
		}
		page.Items, page.NextCursor = nil, ""
		if err := json.Unmarshal(x.call(http.MethodGet, path, admin, "", nil, http.StatusOK), &page); err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Items...)
		if page.NextCursor == "" {
			break
		}
		path = "/api/v1/access/activity?principal=ci%3Aexport&limit=2&cursor=" + url.QueryEscape(page.NextCursor)
	}
	actions := map[string]int{}
	for _, r := range all {
		actions[r.Action]++
	}
	if actions["granted"] != 1 || actions["run_issued"] != 1 || actions["run_revoked"] != 1 || actions["run_used"] == 0 {
		t.Fatalf("activity = %+v", all)
	}
	var found struct {
		Items []row `json:"items"`
	}
	if err := json.Unmarshal(x.call(http.MethodGet, "/api/v1/access/activity?q=JOB%2077", admin, "", nil, http.StatusOK), &found); err != nil ||
		len(found.Items) != 1 || found.Items[0].Action != "run_issued" || found.Items[0].RunID != issued.Run.ID {
		t.Fatalf("search = %+v %v", found, err)
	}

	raw := x.call(http.MethodGet, "/api/v1/access/activity/export?principal=ci%3Aexport", admin, "", nil, http.StatusOK)
	var export struct {
		Kind     string           `json:"kind"`
		Fields   []string         `json:"fields"`
		Excludes []string         `json:"excludes"`
		Rows     int              `json:"rows"`
		Items    []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &export); err != nil || export.Kind != "trstctl.access-activity-export/v1" ||
		export.Rows != len(all) || len(export.Items) != len(all) || !slices.Contains(export.Excludes, "credentials") {
		t.Fatalf("export header = %+v %v (paged rows %d)", export, err, len(all))
	}
	for _, item := range export.Items {
		for key := range item {
			if !slices.Contains(export.Fields, key) {
				t.Fatalf("export row carries undeclared field %q: %+v", key, item)
			}
		}
	}
	runHash, err := auth.HashAPIToken([]byte(issued.Token))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{issued.Token, machine, admin, auth.TokenPrefix, "Bearer", "Authorization", marker, runHash} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("the export carries %q", forbidden[:min(len(forbidden), 12)])
		}
	}
}
