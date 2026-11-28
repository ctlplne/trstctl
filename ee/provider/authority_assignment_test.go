// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProviderAuthorityAssignmentsStayWithinActorPermissions(t *testing.T) {
	now := time.Date(2026, 11, 28, 5, 0, 0, 0, time.UTC)
	access := &customRolesStore{aud58AccessStore: newAUD58AccessStore(), roles: map[string]ProviderRole{
		"access-editor": {Name: "access-editor", Permissions: []Permission{PermOperatorsAdmin}},
		"role-editor":   {Name: "role-editor", Permissions: []Permission{PermRolesAdmin}},
	}}
	for _, identity := range []OperatorIdentity{
		{ID: "limited", Role: "access-editor", Active: true, Source: "scim:test"},
		{ID: "role-editor", Role: "role-editor", Active: true, Source: "scim:test"},
		{ID: "target", Role: OperatorOperator, Active: true, Source: "scim:test"},
	} {
		access.identities[identity.ID] = identity
	}
	customers := NewMemStore()
	if _, err := customers.CreateTenant(t.Context(), Tenant{
		ID: "customer", Slug: "customer", Name: "Customer", Status: TenantActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	sink := &customRolesSink{aud58MutationSink: aud58MutationSink{store: access.aud58AccessStore}, roles: access}
	h := NewHandler(Config{License: providerLicense(t, 10), Store: customers, Mutations: sink,
		Access: access, Delegations: access, Authenticator: headerAuth{}, Clock: func() time.Time { return now }})
	requestNumber := 0
	call := func(actor, role, method, path, body string, want int) {
		t.Helper()
		requestNumber++
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Test-Operator", actor)
		req.Header.Set("X-Test-Role", role)
		req.Header.Set("X-Test-Ceiling", "admin")
		req.Header.Set("Idempotency-Key", fmt.Sprintf("authority-assignment-%d", requestNumber))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s as %s: HTTP %d, want %d: %s", method, path, actor, rec.Code, want, rec.Body.String())
		}
	}
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/limited/role", `{"role":"admin"}`, http.StatusForbidden)
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/target/role", `{"role":"admin"}`, http.StatusForbidden)
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/target/role", `{"role":"access-editor"}`, http.StatusOK)
	if target, err := access.ResolveOperator(t.Context(), "target"); err != nil || target.Role != "access-editor" {
		t.Fatalf("permitted role assignment did not project: %+v, %v", target, err)
	}
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/limited/delegations", `{"customer_id":"customer","operations":["read"]}`, http.StatusForbidden)
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/target/delegations", `{"customer_id":"customer","operations":["offboard"]}`, http.StatusForbidden)
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/target/delegations", `{"customer_id":"customer","operations":["read"]}`, http.StatusCreated)
	call("limited", "access-editor", http.MethodPost, "/provider/v1/operators/limited/revocations", `{"customer_id":"customer","operations":["read"]}`, http.StatusForbidden)
	call("role-editor", "role-editor", http.MethodPut, "/provider/v1/roles/expanded", `{"permissions":["roles:admin","tenants:provision"]}`, http.StatusForbidden)
	call("role-editor", "role-editor", http.MethodPut, "/provider/v1/roles/narrow", `{"permissions":["roles:admin"]}`, http.StatusOK)
}
