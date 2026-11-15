// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// TestServedSecretAccessExplainNamesTheDenyingLayerA235L4 is A235-L4's
// Done-when (served): a project secret in a restricted environment answers to
// separate grants, the subject's permission, its environment membership and,
// on the Vault-compatible KV routes, the tenant's Vault ACL policies for its
// roles. The explain names, per surface, the layer that denies, and each
// verdict is what the surface itself then does: an outsider with
// secrets:read is denied by the environment on all three surfaces; a member
// without secrets:read is denied by its permission on the native and KV
// surfaces while its reference is allowed; a member with secrets:read reads
// natively and over KV until a Vault ACL policy denies the path, when the
// explain names the ACL policy for KV alone and the KV read is refused.
func TestServedSecretAccessExplainNamesTheDenyingLayerA235L4(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	// Its own tenant: its project and its Vault ACL policy must not reach
	// the shared served tenant's other tests.
	const tenant = "a2350004-35a4-4a35-8a35-0000a2350004"
	registerServedTenantID(t, h, tenant, "A235-L4 explain tenant")
	admin := seedScopedTokenSubject(t, h.store, tenant, "a235l4-admin",
		"access:read", "access:write", "secrets:read", "secrets:write", "policy:read", "policy:write", "notifications:write")
	outsider := seedScopedTokenSubject(t, h.store, tenant, "a235l4-outsider", "secrets:read", "notifications:write")
	reader := seedScopedTokenSubject(t, h.store, tenant, "a235l4-reader", "secrets:read", "notifications:write")
	noRead := seedScopedTokenSubject(t, h.store, tenant, "a235l4-noread", "notifications:write")
	call := func(tok, method, path string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReq(t, h, method, path, tok, body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "pay235", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "stage", "restricted": true},
	}}, http.StatusCreated)
	for _, member := range []string{"a235l4-admin", "a235l4-reader", "a235l4-noread"} {
		role := "viewer"
		if member == "a235l4-admin" {
			role = "admin"
		}
		call(admin, http.MethodPut, "/api/v1/secrets/projects/pay235/members/"+member, map[string]any{"role": role, "environments": []string{"stage"}}, http.StatusOK)
	}
	const name = "pay235/stage/db/password"
	call(admin, http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": name, "value": "stage-db-a235l4"}, http.StatusCreated)

	type surface struct {
		Surface  string `json:"surface"`
		Allowed  bool   `json:"allowed"`
		DeniedBy string `json:"denied_by"`
		Layers   []struct {
			Layer   string `json:"layer"`
			Allowed bool   `json:"allowed"`
			Detail  string `json:"detail"`
		} `json:"layers"`
	}
	explain := func(subject string) (string, map[string]surface) {
		t.Helper()
		raw := call(admin, http.MethodGet, "/api/v1/secrets/projects/pay235/members/"+subject+"/access?secret="+name+"&action=read", nil, http.StatusOK)
		var out struct {
			Credentials string    `json:"credentials"`
			Surfaces    []surface `json:"surfaces"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || len(out.Surfaces) != 3 {
			t.Fatalf("explain %s: %s (%v)", subject, raw, err)
		}
		bySurface := map[string]surface{}
		for _, s := range out.Surfaces {
			bySurface[s.Surface] = s
		}
		return out.Credentials, bySurface
	}
	verdict := func(s surface) string {
		if s.Allowed {
			return "allowed"
		}
		return "denied by " + s.DeniedBy
	}
	want := func(subject string, got map[string]surface, native, kv, reference string) {
		t.Helper()
		if verdict(got["native"]) != native || verdict(got["vault_kv"]) != kv || verdict(got["reference"]) != reference {
			t.Fatalf("explain %s: native %s, KV %s, reference %s; want %s, %s, %s (%+v)", subject,
				verdict(got["native"]), verdict(got["vault_kv"]), verdict(got["reference"]), native, kv, reference, got)
		}
	}
	// A notification channel's credential is a secret:// reference; the
	// channel's id is its type, so each caller sets up a different one.
	reference := func(tok, channel string) (int, string) {
		status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/notification-channels", tok, map[string]any{ // #nosec G101 -- a secret:// reference in a test fixture, not a credential value (CWE-798)
			"id": channel, "channel_type": channel, "label": "A235-L4 " + channel, "endpoint_url": "https://notifications.example.test/" + channel,
			"credential_ref": "secret://" + name, "enabled": true,
		})
		return status, string(raw)
	}

	// An outsider with secrets:read: the environment denies on every surface.
	credentials, got := explain("a235l4-outsider")
	if credentials != "api_tokens" {
		t.Fatalf("the outsider's credentials read %q, want api_tokens", credentials)
	}
	want("a235l4-outsider", got, "denied by environment", "denied by environment", "denied by environment")
	call(outsider, http.MethodGet, "/api/v1/secrets/store/"+name, nil, http.StatusNotFound)
	vaultServedRequest(t, h, outsider, http.MethodGet, "/v1/secret/data/"+name, nil, http.StatusNotFound)
	if status, raw := reference(outsider, "webhook"); status != http.StatusForbidden {
		t.Fatalf("the outsider set up a reference into stage: HTTP %d %s", status, raw)
	}

	// A member without secrets:read: its permission denies the native and KV
	// reads; its membership allows the reference.
	_, got = explain("a235l4-noread")
	want("a235l4-noread", got, "denied by permission", "denied by permission", "allowed")
	call(noRead, http.MethodGet, "/api/v1/secrets/store/"+name, nil, http.StatusForbidden)
	vaultServedRequest(t, h, noRead, http.MethodGet, "/v1/secret/data/"+name, nil, http.StatusForbidden)
	if status, raw := reference(noRead, "webhook"); status != http.StatusCreated {
		t.Fatalf("a stage member's reference was refused: HTTP %d %s", status, raw)
	}

	// A member with secrets:read reads natively and over KV ...
	_, got = explain("a235l4-reader")
	want("a235l4-reader", got, "allowed", "allowed", "allowed")
	if layers := got["vault_kv"].Layers; len(layers) != 3 || layers[2].Layer != "acl_policy" || !strings.Contains(layers[2].Detail, "no Vault ACL policy") {
		t.Fatalf("the reader's KV layers before any ACL policy: %+v", layers)
	}
	if raw := call(reader, http.MethodGet, "/api/v1/secrets/store/"+name, nil, http.StatusOK); !strings.Contains(string(raw), "stage-db-a235l4") {
		t.Fatalf("the reader's native read: %s", raw)
	}
	if raw := vaultServedRequest(t, h, reader, http.MethodGet, "/v1/secret/data/"+name, nil, http.StatusOK); !strings.Contains(string(raw), "stage-db-a235l4") {
		t.Fatalf("the reader's KV read: %s", raw)
	}
	// ... until a Vault ACL policy for its role denies the path: then the
	// explain names the ACL policy for KV alone, and the KV read is refused.
	vaultServedRequest(t, h, admin, http.MethodPut, "/v1/sys/policies/acl/api-token", map[string]any{
		"policy": `path "secret/data/pay235/stage/*" { capabilities = ["deny"] }`,
	}, http.StatusNoContent)
	_, got = explain("a235l4-reader")
	want("a235l4-reader", got, "allowed", "denied by acl_policy", "allowed")
	call(reader, http.MethodGet, "/api/v1/secrets/store/"+name, nil, http.StatusOK)
	vaultServedRequest(t, h, reader, http.MethodGet, "/v1/secret/data/"+name, nil, http.StatusForbidden)
	if status, raw := reference(reader, "pagerduty"); status != http.StatusCreated {
		t.Fatalf("the reader's reference was refused: HTTP %d %s", status, raw)
	}

	// A tenant member's permissions come from its member roles: a viewer
	// granted stage still has no secrets:read.
	if _, err := h.srv.orch.UpsertTenantMember(t.Context(), tenant, store.TenantMember{
		Subject: "a235l4-person", DisplayName: "A235-L4 Person", Roles: []string{"viewer"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	call(admin, http.MethodPut, "/api/v1/secrets/projects/pay235/members/a235l4-person", map[string]any{"role": "viewer", "environments": []string{"stage"}}, http.StatusOK)
	credentials, got = explain("a235l4-person")
	if credentials != "member" {
		t.Fatalf("a tenant member's credentials read %q, want member", credentials)
	}
	want("a235l4-person", got, "denied by permission", "denied by permission", "allowed")

	// The explain is not the subject's to read without access:read, and it
	// names only a secret of the project.
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/projects/pay235/members/a235l4-reader/access?secret="+name, reader, nil); status != http.StatusForbidden {
		t.Fatalf("explain without access:read: HTTP %d %s", status, raw)
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/projects/pay235/members/a235l4-reader/access?secret=other/stage/x", admin, nil); status != http.StatusBadRequest {
		t.Fatalf("explain of another project's secret: HTTP %d %s", status, raw)
	}
	t.Log("A235L4_OK")
}
