// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import "trstctl.com/trstctl/internal/authz"

// A role-grant fixture holds every permission of each role it actually grants.
func roleAssignerScopes(roleNames ...string) []string {
	scopes := []string{string(authz.AccessWrite), string(authz.AccessRoleAssign)}
	for _, roleName := range roleNames {
		for _, p := range authz.BuiltinRoles()[roleName].Permissions {
			scopes = append(scopes, string(p))
		}
	}
	return scopes
}
