// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

const a207Tenant = "20700000-0000-4000-8000-000000000001"

type a207Deployment struct {
	ts        *httptest.Server
	tokenFile string
	admin     string
	sessions  *auth.SessionIssuer
}

func newA207Deployment(t *testing.T, scimToken string, groupRoles map[string]string) *a207Deployment {
	t.Helper()
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: a207Tenant, Name: "payments"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	d := &a207Deployment{tokenFile: t.TempDir() + "/scim.token"}
	d.admin = seedServedAPIToken(t, ctx, st, a207Tenant, "platform-admin", []string{
		string(authz.AccessRead), string(authz.AccessWrite), string(authz.AccessRoleAssign),
		string(authz.CertsRead), string(authz.CertsRequest),
	})
	if err := writeSecretFile(d.tokenFile, []byte(scimToken)); err != nil {
		t.Fatalf("write scim token file: %v", err)
	}
	d.sessions = auth.NewSessionIssuer([]byte("a207-session-secret-012345678901234"), time.Hour)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: st, Log: log,
		SCIM: config.SCIM{Enabled: true, Tokens: []config.SCIMToken{{
			Name: "okta", TenantID: a207Tenant, TokenFile: d.tokenFile, GroupRoles: groupRoles,
		}}},
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true, Sessions: d.sessions})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	d.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(d.ts.Close)
	return d
}

type a207Me struct {
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (d *a207Deployment) me(t *testing.T, session string) a207Me {
	t.Helper()
	code, body := doSession(t, d.ts, http.MethodGet, "/auth/me", session)
	if code != http.StatusOK {
		t.Fatalf("auth/me = %d %s", code, body)
	}
	var me a207Me
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	return me
}

func a207Group(name string, members ...string) map[string]any {
	group := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": name}
	var list []map[string]string
	for _, m := range members {
		list = append(list, map[string]string{"value": m})
	}
	group["members"] = list
	return group
}

// A207: a tenant defines a custom role from permissions its administrator
// holds; a SCIM group the token maps to it grants exactly that role, so a
// member's session gains its permissions and nothing else. An unmapped group,
// a group named for the custom role without a mapping, and a group mapped to
// a role the tenant has not defined all grant nothing. A held role cannot be
// deleted; once no member holds it, it can.
func TestServedSCIMGroupMapGrantsTenantCustomRoles(t *testing.T) {
	const scimToken = "a207-scim-token-one" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	d := newA207Deployment(t, scimToken, map[string]string{"payments-ops": "payments-operator", "auditors-plus": "audit-plus"})

	if code, body := doBearer(t, d.ts, http.MethodPut, "/api/v1/access/roles/payments-operator", d.admin, "a207-too-broad",
		map[string]any{"permissions": []string{"certs:read", "keys:approve"}}); code != http.StatusForbidden || !bytes.Contains(body, []byte("keys:approve")) {
		t.Fatalf("a role broader than its author = %d %s", code, body)
	}
	if code, body := doBearer(t, d.ts, http.MethodPut, "/api/v1/access/roles/viewer", d.admin, "a207-builtin",
		map[string]any{"permissions": []string{"certs:read"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("redefining a built-in role = %d %s", code, body)
	}
	code, body := doBearer(t, d.ts, http.MethodPut, "/api/v1/access/roles/payments-operator", d.admin, "a207-define",
		map[string]any{"description": "payments certificate operations", "permissions": []string{"certs:read", "certs:request"}})
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"custom":true`)) {
		t.Fatalf("define payments-operator = %d %s", code, body)
	}
	if code, body := doBearer(t, d.ts, http.MethodGet, "/api/v1/access/roles", d.admin, "", nil); code != http.StatusOK ||
		!bytes.Contains(body, []byte(`"name":"payments-operator"`)) {
		t.Fatalf("role list = %d %s", code, body)
	}

	user := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "alice@example.com",
		"displayName": "Alice Example", "active": true}
	created := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Users", scimToken, "a207-user", user)
	if created.Code != http.StatusCreated {
		t.Fatalf("create user = %d %s", created.Code, created.Body)
	}
	alice := scimID(t, created.Body.Bytes())
	session, err := d.sessions.Issue("alice@example.com", a207Tenant, "alice@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Groups that grant nothing.
	for i, name := range []string{"random-team", "payments-operator", "auditors-plus"} {
		got := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", scimToken, "a207-refused-"+string(rune('a'+i)), a207Group(name, alice))
		if got.Code != http.StatusBadRequest {
			t.Fatalf("group %s = %d %s, want 400", name, got.Code, got.Body)
		}
	}
	if refused := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", scimToken, "a207-undefined", a207Group("auditors-plus", alice)); !bytes.Contains(refused.Body.Bytes(), []byte("audit-plus")) {
		t.Fatalf("a group mapped to an undefined role does not say which: %s", refused.Body)
	}
	if me := d.me(t, session); len(me.Roles) != 0 || slices.Contains(me.Permissions, "certs:request") {
		t.Fatalf("after refused groups alice holds %+v", me)
	}

	// The mapped group grants the custom role and only its permissions.
	pushed := doSCIM(t, d.ts, http.MethodPost, "/scim/v2/Groups", scimToken, "a207-mapped", a207Group("payments-ops", alice))
	if pushed.Code != http.StatusCreated || scimID(t, pushed.Body.Bytes()) != "payments-ops" {
		t.Fatalf("mapped group = %d %s", pushed.Code, pushed.Body)
	}
	me := d.me(t, session)
	if !slices.Equal(me.Roles, []string{"payments-operator"}) || !slices.Contains(me.Permissions, "certs:request") ||
		!slices.Contains(me.Permissions, "certs:read") || slices.Contains(me.Permissions, "access:read") {
		t.Fatalf("alice through payments-ops = %+v", me)
	}
	if code, body := doSession(t, d.ts, http.MethodGet, "/api/v1/endpoints/verifications", session); code != http.StatusOK {
		t.Fatalf("certs:read through the custom role = %d %s", code, body)
	}
	if code, _ := doSession(t, d.ts, http.MethodGet, "/api/v1/access/members", session); code != http.StatusForbidden {
		t.Fatalf("access:read without the role = %d", code)
	}
	if got := doSCIM(t, d.ts, http.MethodGet, "/scim/v2/Groups/payments-ops", scimToken, "", nil); got.Code != http.StatusOK ||
		!bytes.Contains(got.Body.Bytes(), []byte(`"value":"alice@example.com"`)) {
		t.Fatalf("mapped group read = %d %s", got.Code, got.Body)
	}

	// A held role cannot be deleted; after the group drops alice it can, and
	// her session loses its permissions.
	if code, body := doBearer(t, d.ts, http.MethodDelete, "/api/v1/access/roles/payments-operator", d.admin, "a207-delete-held", nil); code != http.StatusConflict {
		t.Fatalf("delete a held role = %d %s", code, body)
	}
	remove := map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "remove", "path": "members", "value": []map[string]string{{"value": alice}}}}}
	if got := doSCIM(t, d.ts, http.MethodPatch, "/scim/v2/Groups/"+url.PathEscape("payments-ops"), scimToken, "a207-remove", remove); got.Code != http.StatusOK {
		t.Fatalf("remove alice = %d %s", got.Code, got.Body)
	}
	if code, body := doBearer(t, d.ts, http.MethodDelete, "/api/v1/access/roles/payments-operator", d.admin, "a207-delete", nil); code != http.StatusNoContent {
		t.Fatalf("delete an unheld role = %d %s", code, body)
	}
	if me := d.me(t, session); slices.Contains(me.Permissions, "certs:request") {
		t.Fatalf("after the deletion alice holds %+v", me)
	}
}

// A207: rotating a tenant SCIM token is writing its file. The old token stops
// working and the new one works without a restart; a broken rewrite keeps
// the last good token.
func TestServedSCIMTokenRotatesWithoutRestart(t *testing.T) {
	saved := scimTokenRecheck
	scimTokenRecheck = 0
	t.Cleanup(func() { scimTokenRecheck = saved })
	const first, second = "a207-rotate-token-first", "a207-rotate-token-second-longer" // #nosec G101 -- fabricated fixture credentials (CWE-798)
	d := newA207Deployment(t, first, nil)
	read := func(token string) int {
		return doSCIM(t, d.ts, http.MethodGet, "/scim/v2/ServiceProviderConfig", token, "", nil).Code
	}
	if code := read(first); code != http.StatusOK {
		t.Fatalf("first token = %d", code)
	}
	if err := writeSecretFile(d.tokenFile, []byte(second)); err != nil {
		t.Fatal(err)
	}
	if old, rotated := read(first), read(second); old != http.StatusUnauthorized || rotated != http.StatusOK {
		t.Fatalf("after rotation old = %d, new = %d; want 401 and 200", old, rotated)
	}
	if err := writeSecretFile(d.tokenFile, []byte("  \n")); err != nil {
		t.Fatal(err)
	}
	if code := read(second); code != http.StatusOK {
		t.Fatalf("after an empty rewrite the last good token = %d", code)
	}
}
