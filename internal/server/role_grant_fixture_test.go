// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// seedRoleGrantingTokenSubject gives a test actor the exact permissions of the
// built-in role it grants. The actor has no wildcard or unrelated privileges.
func seedRoleGrantingTokenSubject(t *testing.T, st *store.Store, tenant, subject, role string, extra ...string) string {
	t.Helper()
	builtin, ok := authz.BuiltinRoles()[role]
	if !ok {
		t.Fatalf("unknown built-in role %q", role)
	}
	scopes := append([]string(nil), extra...)
	for _, permission := range builtin.Permissions {
		scopes = append(scopes, string(permission))
	}
	return seedScopedTokenSubject(t, st, tenant, subject, scopes...)
}
