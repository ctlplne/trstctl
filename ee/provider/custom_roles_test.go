// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// A90: arbitrary custom Provider operator roles.
//
// The Provider plane knew two roles, admin and operator, and every mutation
// asked "is this an admin?". A Provider admin can now define a named role as
// a subset of the fixed Provider permission vocabulary, store it as an
// immutable authority event, assign it through the role route or SCIM, and
// every gate asks for the permission instead of the name. The signed IdP role
// stays a ceiling: a custom role never grants what the IdP role would not.

type customRolesStore struct {
	*aud58AccessStore
	mu    sync.Mutex
	roles map[string]ProviderRole
}

func (s *customRolesStore) ListRoles(context.Context) ([]ProviderRole, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ProviderRole, 0, len(s.roles))
	for _, role := range s.roles {
		out = append(out, role)
	}
	return out, nil
}

type customRolesSink struct {
	aud58MutationSink
	roles *customRolesStore
}

func (s *customRolesSink) Append(ctx context.Context, key, typ, tenantID string, payload AuthorityEvent) (eventspec.Event, error) {
	event, err := s.aud58MutationSink.Append(ctx, key, typ, tenantID, payload)
	if err != nil {
		return event, err
	}
	if payload.Role != nil {
		s.roles.mu.Lock()
		if typ == EventRoleDeleted {
			delete(s.roles.roles, payload.Role.Name)
		} else {
			s.roles.roles[payload.Role.Name] = *payload.Role
		}
		s.roles.mu.Unlock()
	}
	return event, nil
}

// headerAuth authenticates an operator described by request headers, so one
// handler can be driven as an admin, a custom-role holder, and a holder whose
// IdP ceiling is lower than the role.
type headerAuth struct{}

func (headerAuth) AuthenticateOperator(r *http.Request) (Operator, bool) {
	id := r.Header.Get("X-Test-Operator")
	if id == "" {
		return Operator{}, false
	}
	role := OperatorRole(r.Header.Get("X-Test-Role"))
	ceiling := OperatorRole(r.Header.Get("X-Test-Ceiling"))
	if ceiling == "" {
		ceiling = OperatorAdmin
	}
	return Operator{ID: id, Email: id + "@provider.example", Role: role, Ceiling: ceiling, MFA: true}, true
}

func TestCustomProviderRolesGateByPermissionA90(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 23, 5, 0, 0, 0, time.UTC)
	access := &customRolesStore{aud58AccessStore: newAUD58AccessStore(), roles: map[string]ProviderRole{}}
	access.identities["op-admin"] = OperatorIdentity{ID: "op-admin", ExternalID: "op-admin", UserName: "admin@provider.example", Role: OperatorAdmin, Active: true, Source: "scim:test", CreatedAt: now, UpdatedAt: now}
	access.identities["op-casey"] = OperatorIdentity{ID: "op-casey", ExternalID: "op-casey", UserName: "casey@provider.example", Role: OperatorOperator, Active: true, Source: "scim:test", CreatedAt: now, UpdatedAt: now}
	sink := &customRolesSink{aud58MutationSink: aud58MutationSink{store: access.aud58AccessStore}, roles: access}
	rawToken := "a90-provider-scim-secret" // #nosec G101 -- deterministic non-deployable test bearer exercises hashing/authentication (CWE-798).
	h := NewHandler(Config{
		License: providerLicense(t, 10), Mutations: sink, Access: access, Delegations: access, Authenticator: headerAuth{},
		Clock: func() time.Time { return now },
		SCIM:  &SCIMConfig{Tokens: []SCIMToken{{Name: "entra", TokenHash: crypto.SHA256Hex([]byte(rawToken))}}},
	})
	call := func(method, path, body, operator, role, ceiling string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Test-Operator", operator)
		req.Header.Set("X-Test-Role", role)
		req.Header.Set("X-Test-Ceiling", ceiling)
		req.Header.Set("Idempotency-Key", "a90:"+method+":"+path+":"+body+":"+operator+":"+role+":"+ceiling)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	admin := func(method, path, body string) *httptest.ResponseRecorder {
		return call(method, path, body, "op-admin", "admin", "admin")
	}

	// Only an admin defines roles; the vocabulary is closed and built-in names
	// are reserved.
	if rec := call(http.MethodPut, "/provider/v1/roles/lifecycle", `{"description":"x","permissions":["tenants:lifecycle"]}`, "op-casey", "operator", "operator"); rec.Code != http.StatusForbidden {
		t.Fatalf("operator defining a role = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodPut, "/provider/v1/roles/lifecycle", `{"description":"x","permissions":["tenants:delete-everything"]}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenants:delete-everything") {
		t.Fatalf("unknown permission = %d %s, want 400 naming it", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodPut, "/provider/v1/roles/admin", `{"description":"x","permissions":["tenants:lifecycle"]}`); rec.Code != http.StatusConflict {
		t.Fatalf("redefining admin = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodPut, "/provider/v1/roles/Bad_Name", `{"permissions":["tenants:lifecycle"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role name = %d, want 400", rec.Code)
	}
	rec := admin(http.MethodPut, "/provider/v1/roles/provisioner", `{"description":"defines roles, nothing else","permissions":["roles:admin","breakglass:results"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("define role = %d %s", rec.Code, rec.Body.String())
	}
	var defined ProviderRole
	if err := json.Unmarshal(rec.Body.Bytes(), &defined); err != nil || defined.Name != "provisioner" || len(defined.Permissions) != 2 || defined.CreatedBy != "op-admin" || defined.BuiltIn {
		t.Fatalf("defined role = %+v %v", defined, err)
	}
	rec = admin(http.MethodGet, "/provider/v1/roles", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list roles = %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Roles       []ProviderRole `json:"roles"`
		Permissions []struct {
			Name string `json:"name"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, role := range list.Roles {
		names[role.Name] = true
		if (role.Name == "admin" || role.Name == "operator") && !role.BuiltIn {
			t.Fatalf("built-in role %s not marked built-in", role.Name)
		}
	}
	if !names["admin"] || !names["operator"] || !names["provisioner"] || len(list.Permissions) == 0 {
		t.Fatalf("role list = %s, want the built-ins, the custom role and the permission vocabulary", rec.Body.String())
	}

	// The role route assigns it; the identity carries the custom name.
	rec = admin(http.MethodPost, "/provider/v1/operators/op-casey/role", `{"role":"provisioner"}`)
	if rec.Code != http.StatusOK || access.identities["op-casey"].Role != "provisioner" {
		t.Fatalf("assign custom role = %d %s identity=%+v", rec.Code, rec.Body.String(), access.identities["op-casey"])
	}
	if rec := admin(http.MethodPost, "/provider/v1/operators/op-casey/role", `{"role":"nonexistent"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("assign undefined role = %d %s, want 400", rec.Code, rec.Body.String())
	}

	// The holder can do what the role says and nothing else.
	casey := func(method, path, body string) *httptest.ResponseRecorder {
		return call(method, path, body, "op-casey", "provisioner", "admin")
	}
	if rec := casey(http.MethodPut, "/provider/v1/roles/scratch", `{"permissions":["breakglass:results"]}`); rec.Code != http.StatusOK {
		t.Fatalf("role-editor defining a role = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := casey(http.MethodPost, "/provider/v1/tenants", `{"slug":"acme","name":"Acme"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("role-editor provisioning = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := casey(http.MethodPost, "/provider/v1/isolation-drill", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("role-editor running a drill = %d, want 403", rec.Code)
	}
	if rec := casey(http.MethodGet, "/provider/v1/operators", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("role-editor reading the workforce = %d, want 403", rec.Code)
	}
	rec = casey(http.MethodGet, "/provider/v1/auth/session", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"roles_write":true`) || !strings.Contains(rec.Body.String(), `"isolation_drill":false`) || !strings.Contains(rec.Body.String(), `"access_write":false`) {
		t.Fatalf("session authority for the custom role = %d %s", rec.Code, rec.Body.String())
	}
	// The IdP role is a ceiling: an operator-level sign-in holding the same
	// custom role cannot define roles, because the operator set does not.
	if rec := call(http.MethodPut, "/provider/v1/roles/scratch2", `{"permissions":["breakglass:results"]}`, "op-casey", "provisioner", "operator"); rec.Code != http.StatusForbidden {
		t.Fatalf("custom role above the IdP ceiling = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodDelete, "/provider/v1/roles/scratch", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete scratch role = %d %s", rec.Code, rec.Body.String())
	}

	// SCIM assigns a defined custom role and refuses an undefined one.
	scim := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/provider/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := scim(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"entra-77","userName":"jo@provider.example","active":true,"roles":[{"value":"provisioner"}]}`); rec.Code != http.StatusCreated {
		t.Fatalf("SCIM joiner with a custom role = %d %s", rec.Code, rec.Body.String())
	}
	if identity, err := access.ResolveOperator(t.Context(), "entra-77"); err != nil || identity.Role != "provisioner" {
		t.Fatalf("SCIM joiner identity = %+v %v, want the custom role", identity, err)
	}
	if rec := scim(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"entra-78","userName":"kim@provider.example","active":true,"roles":[{"value":"ghost"}]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("SCIM joiner with an undefined role = %d %s, want 400", rec.Code, rec.Body.String())
	}

	// A role in use cannot be deleted; once nobody holds it, it can.
	if rec := admin(http.MethodDelete, "/provider/v1/roles/provisioner", ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "op-casey") {
		t.Fatalf("delete a held role = %d %s, want 409 naming a holder", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"op-casey", "entra-77"} {
		identity, _ := access.ResolveOperator(t.Context(), id)
		if rec := admin(http.MethodPost, "/provider/v1/operators/"+identity.ID+"/role", `{"role":"operator"}`); rec.Code != http.StatusOK {
			t.Fatalf("reassign %s = %d %s", id, rec.Code, rec.Body.String())
		}
	}
	if rec := admin(http.MethodDelete, "/provider/v1/roles/provisioner", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete an unused role = %d %s, want 204", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodDelete, "/provider/v1/roles/admin", ""); rec.Code != http.StatusConflict {
		t.Fatalf("delete a built-in role = %d, want 409", rec.Code)
	}
	// A deleted role on a stale session grants nothing.
	if rec := casey(http.MethodPut, "/provider/v1/roles/scratch3", `{"permissions":["breakglass:results"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("deleted role still defining roles = %d, want 403", rec.Code)
	}
}
