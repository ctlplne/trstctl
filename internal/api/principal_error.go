// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// principalRoles returns the distinct role names a principal holds, for audit
// attribution (the "under what authorization").
func principalRoles(p authz.Principal) []string {
	seen := map[string]bool{}
	var roles []string
	for _, g := range p.Grants {
		if g.Role.Name != "" && !seen[g.Role.Name] {
			seen[g.Role.Name] = true
			roles = append(roles, g.Role.Name)
		}
	}
	return roles
}

// apiError lets a handler choose the problem status for a domain failure.
type apiError struct {
	status int
	detail string
	ext    map[string]any
}

func (e *apiError) Error() string { return e.detail }

func errStatus(status int, detail string) *apiError {
	return &apiError{status: status, detail: detail}
}
